"""
Feature test suite (CSRF, roles, record types, links, alerts, audit, backups, playbook).
Run from the project root:   python tests/test_features.py
Prints PASS/FAIL per check and a summary; exit code 1 if anything fails.
"""
import os, re, io, json, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TMP = tempfile.mkdtemp(prefix="cv-tests-")
os.environ.update(DATABASE_URL="sqlite:///" + TMP + "/test.db", BACKUP_DIR=TMP + "/bk", UPLOAD_DIR=TMP + "/uploads", SECRET_KEY="test-secret-key-123", VAULT_KEY="")
import app as A
from datetime import date, timedelta, datetime
import ops, backup
BK = TMP + "/bk"
RT = TMP + "/restore_t"

ok_n=fail_n=0
def check(name, cond, extra=""):
    global ok_n, fail_n
    if cond: ok_n+=1; print(f"  PASS  {name}")
    else: fail_n+=1; print(f"  FAIL  {name} {extra}")

def login(c, uid):
    with c.session_transaction() as s: s["_user_id"]=str(uid); s["_fresh"]=True
def token(c):
    html=c.get("/expiring").get_data(as_text=True)
    m=re.search(r'name="csrf-token" content="([^"]+)"',html); return m.group(1)
def post(c, url, data=None, **kw):
    d=dict(data or {}); d["csrf_token"]=token(c); return c.post(url, data=d, **kw)

with A.app.app_context():
    admin=A.User.query.first(); admin.must_change_password=False
    tech=A.User(email="tech@x.com"); A.apply_role(tech,"tech"); tech.set_password("Techpass123!")
    ro=A.User(email="ro@x.com"); A.apply_role(ro,"readonly"); ro.set_password("Readpass123!")
    A.db.session.add_all([tech,ro])
    o1=A.Organization(name="Acme"); o2=A.Organization(name="Other"); A.db.session.add_all([o1,o2]); A.db.session.commit()
    ids=dict(admin=admin.id,tech=tech.id,ro=ro.id,o1=o1.id,o2=o2.id)
    A.db.session.add(A.Domain(org_id=o1.id,domain_name="acme.com",expires_on=date.today()+timedelta(days=10)))
    A.db.session.add(A.Asset(org_id=o1.id,device_name="LAP-1",warranty_expires=date.today()+timedelta(days=5)))
    pw=A.Password(org_id=o1.id,name="Firewall",username_plain=A.encrypt_secret("admin"),password_plain=A.encrypt_secret("fw-Secret!1"))
    A.db.session.add(pw); A.db.session.commit(); ids["pw"]=pw.id
    pw2=A.Password(org_id=o2.id,name="OtherOrgPw",username_plain=A.encrypt_secret("x"),password_plain=A.encrypt_secret("y")); A.db.session.add(pw2); A.db.session.commit(); ids["pw2"]=pw2.id

ca,ct,cr=A.app.test_client(),A.app.test_client(),A.app.test_client()
login(ca,ids["admin"]); login(ct,ids["tech"]); login(cr,ids["ro"])
for c in (ca,ct,cr):
    with c.session_transaction() as s: s["active_org_id"]=ids["o1"]

print("\n== CSRF")
r=ca.post(f"/orgs/new",data={"name":"NoToken"}); 
with A.app.app_context(): check("POST without token is rejected", A.Organization.query.filter_by(name="NoToken").first() is None)
r=post(ca,"/orgs/new",{"name":"WithToken","description":""})
with A.app.app_context(): check("POST with token succeeds", A.Organization.query.filter_by(name="WithToken").first() is not None)
html=ca.get(f"/passwords/{ids['pw']}/view").get_data(as_text=True)
forms=re.findall(r'<form\b[^>]*method="post"[^>]*>(?:\s*)<input type="hidden" name="csrf_token"',html,re.I)
allposts=len(re.findall(r'<form\b[^>]*method="post"',html,re.I))
check("every POST form on a page got a token", allposts>0 and len(forms)==allposts, f"{len(forms)}/{allposts}")
tok=token(ca)
r=ca.post(f"/orgs/new",data={"name":"HdrTok"},headers={"X-CSRFToken":tok,"X-Requested-With":"fetch"})
with A.app.app_context(): check("fetch-style header token works", A.Organization.query.filter_by(name="HdrTok").first() is not None)
check("session cookie is SameSite=Lax", A.app.config["SESSION_COOKIE_SAMESITE"]=="Lax")
# public share link still works with no cookies/token
r=post(ca,f"/passwords/{ids['pw']}/share",{"expires_minutes":"5"})
v=ca.get(f"/passwords/{ids['pw']}/view").get_data(as_text=True)
link=re.search(r'value="(http[^"]+/shared/password/[^"]+)"',v).group(1).split("localhost")[1]
anon=A.app.test_client()
check("share reveal works for anonymous recipient (CSRF-exempt)", "fw-Secret!1" in anon.post(link).get_data(as_text=True))
check("login page still renders with token", b"csrf" in anon.get("/login").data.lower())

print("\n== Roles")
n_before=0
with A.app.app_context(): n_before=A.Password.query.count()
r=post(cr,"/passwords/new",{"name":"RO attempt","username":"u","password":"p"})
with A.app.app_context(): check("read-only user cannot create", A.Password.query.count()==n_before)
check("read-only user can view", cr.get(f"/passwords/{ids['pw']}/view").status_code==200)
r=post(cr,f"/passwords/{ids['pw']}/share",{"expires_minutes":"5"})
with A.app.app_context(): check("read-only cannot share", A.PasswordShareLink.query.count()==1)
r=cr.post("/orgs/new",data={"name":"x"},headers={"X-CSRFToken":token(cr),"X-Requested-With":"fetch"}); check("read-only fetch POST gets JSON 403", r.status_code==403 and r.is_json)
r=post(ct,"/passwords/new",{"name":"Tech pw","username":"u","password":"Abcdef123!x"})
with A.app.app_context(): check("tech can create", A.Password.query.filter_by(name="Tech pw").first() is not None)
check("tech blocked from admin audit", ct.get("/admin/audit").status_code in (302,403))
check("tech blocked from admin types", ct.get("/admin/types").status_code in (302,403))
check("tech blocked from backups", ct.get("/admin/backups").status_code in (302,403))
check("admin can open audit", ca.get("/admin/audit").status_code==200)
r=post(ct,f"/orgs/{ids['o1']}/export",{"sections":["overview"],"credentials":"full","confirm_password":"Techpass123!","pdf_password":"x"*14})
check("tech cannot export passwords", r.status_code==302)
# last admin guard
r=post(ca,f"/admin/users/{ids['admin']}/edit",{"email":"admin@local","role":"tech","is_active_user":"1"})
with A.app.app_context(): check("cannot demote the only admin", A.user_role(db_u:=A.db.session.get(A.User,ids['admin']))=="admin")
r=post(ca,"/admin/users/new",{"email":"new@x.com","password":"Newpass123!x","role":"readonly"})
with A.app.app_context():
    u=A.User.query.filter_by(email="new@x.com").first(); check("admin creates read-only user via role select", u and A.user_role(u)=="readonly" and not u.is_super_admin)

print("\n== Custom types & records")
form={"name":"Licence","plural":"Licences","description":"d",
 "f_key":["","",""],"f_label":["Vendor","Licence key","Renewal date"],"f_type":["text","password","date"],
 "f_options":["","",""],"f_required":["1","0","0"],"f_alert":["0","0","1"]}
r=post(ca,"/admin/types/new",form)
with A.app.app_context():
    t=A.CustomType.query.first(); check("type created with 3 fields", t and len(t.fields)==3 and t.fields[2].get("alert") is True); tid=t.id
check("sidebar lists the new type", b"Licences" in ca.get("/expiring").data)
r=post(ct,f"/records/{tid}/new",{"name":"M365 licence","f_vendor":"Microsoft","f_licence_key":"AAAA-BBBB","f_renewal_date":(date.today()+timedelta(days=20)).isoformat()})
with A.app.app_context():
    rec=A.CustomRecord.query.first(); check("tech creates record", rec is not None); rid=rec.id
    check("password field stored encrypted", "AAAA-BBBB" not in rec.data_json and A.decrypt_secret(rec.data["licence_key"])=="AAAA-BBBB")
r=post(ct,f"/records/{tid}/new",{"name":"","f_vendor":"x"}); 
with A.app.app_context(): check("required name enforced", A.CustomRecord.query.count()==1)
r=post(ct,f"/records/{tid}/new",{"name":"Bad date","f_vendor":"v","f_renewal_date":"not-a-date"})
with A.app.app_context(): check("invalid date rejected", A.CustomRecord.query.count()==1)
page=ct.get(f"/record/{rid}").get_data(as_text=True)
check("record view shows fields + masked password", "Microsoft" in page and "AAAA-BBBB" not in page and "In 20 day(s)" in page)
check("reveal endpoint returns secret", ct.get(f"/record/{rid}/secret/licence_key").json["value"]=="AAAA-BBBB")
post(ct,f"/record/{rid}/edit",{"name":"M365 licence v2","f_vendor":"MS","f_licence_key":"","f_renewal_date":(date.today()+timedelta(days=20)).isoformat()})
with A.app.app_context(): check("blank password on edit keeps existing", A.decrypt_secret(A.db.session.get(A.CustomRecord,rid).data["licence_key"])=="AAAA-BBBB")
post(cr,f"/record/{rid}/delete")
with A.app.app_context(): check("read-only cannot delete record", A.db.session.get(A.CustomRecord,rid) is not None)
check("record shows in global search", any(x["title"]=="M365 licence v2" for x in ca.get("/search/global?q=M365").json["results"]) if ca.get("/search/global?q=M365").is_json else False)
post(ct,f"/records/{tid}/new",{"name":"<script>alert(1)</script>","f_vendor":"v"})
lst=ct.get(f"/records/{tid}").data
check("script in name is escaped", b"<script>alert(1)</script>" not in lst and b"&lt;script&gt;alert(1)" in lst)

print("\n== Record links")
r=post(ct,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":f"record:{rid}"},headers={"Referer":"/x"})
pwpage=ca.get(f"/passwords/{ids['pw']}/view").get_data(as_text=True); recpage=ca.get(f"/record/{rid}").get_data(as_text=True)
check("link visible on password page", "M365 licence v2" in pwpage and "Related items" in pwpage)
check("link visible (two-way) on record page", "Firewall" in recpage)
post(ct,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":f"record:{rid}"})
with A.app.app_context(): check("duplicate link not created", A.RecordLink.query.count()==1)
post(ct,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":f"password:{ids['pw2']}"})
with A.app.app_context(): check("cross-organisation link refused", A.RecordLink.query.count()==1)
post(ct,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":f"domain:1"})
s=ct.get(f"/links/search?kind=record:{tid}&q=M365").json; check("link search works", len(s)==1 and s[0]["ref"]==f"record:{rid}")
post(cr,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":"domain:1"})
with A.app.app_context(): check("read-only cannot link", A.RecordLink.query.count()==2)
with A.app.app_context():
    d=A.Domain.query.first(); A.db.session.delete(d); A.db.session.commit()
    check("deleting a record removes its links", A.RecordLink.query.count()==1)
    lid=A.RecordLink.query.first().id
post(ct,f"/links/{lid}/delete")
with A.app.app_context(): check("unlink works", A.RecordLink.query.count()==0)
post(ct,"/links/add",{"a_type":"password","a_id":ids["pw"],"b":f"record:{rid}"})  # relink for playbook test
with A.app.app_context():
    A.db.session.add(A.Domain(org_id=ids["o1"],domain_name="acme.com",expires_on=date.today()+timedelta(days=10))); A.db.session.commit()

print("\n== Expiry tracking & alerts")
page=ca.get("/expiring?window=90").get_data(as_text=True)
check("expiring page lists domain, warranty and record date", "acme.com" in page and "LAP-1" in page and "M365 licence v2" in page)
sent=[]
with A.app.app_context():
    ops._CTX.send_email=lambda to,sub,body: sent.append((to,sub,body))
r=post(ca,"/admin/alerts",{"action":"save","enabled":"1","recipients":"boss@x.com, bad-address, ops@x.com","days":"30,14,7,1"})
with A.app.app_context(): st=ops.get_settings(); check("settings saved; invalid email dropped", st.enabled and st.recipients=="boss@x.com, ops@x.com", st.recipients)
with A.app.app_context():
    res=ops.run_alerts(base_url="https://vault.example.com")
check("first run sends digest to both recipients", res["sent"]==2 and len(sent)==2, str(res))
check("digest names items and has links", "acme.com" in sent[0][2] and "LAP-1" in sent[0][2] and "https://vault.example.com/" in sent[0][2])
sent.clear()
with A.app.app_context(): res=ops.run_alerts()
check("second run sends nothing (dedup)", res["sent"]==0 and not sent, str(res))
with A.app.app_context():
    d=A.Domain.query.first(); d.expires_on=date.today()+timedelta(days=3); A.db.session.commit()   # moved into a closer window
    res=ops.run_alerts()
check("closer window triggers again", res["sent"]==2 and any("acme.com" in x[2] for x in sent), str(res))
sent.clear()
with A.app.app_context():
    d=A.Domain.query.first(); d.expires_on=date.today()-timedelta(days=2); A.db.session.commit()
    res=ops.run_alerts()
check("expired item reported once", res["sent"]==2 and "EXPIRED" in sent[0][2])
sent.clear()
with A.app.app_context():
    d=A.Domain.query.first(); d.expires_on=date.today()+timedelta(days=300); A.db.session.commit()   # renewed
    d.expires_on=date.today()+timedelta(days=6); A.db.session.commit()                              # next year: re-arm
    res=ops.run_alerts()
check("renewed then expiring again re-arms", res["sent"]==2)
with A.app.app_context():
    st=ops.get_settings(); st.enabled=False; A.db.session.commit(); res=ops.run_alerts(); st.enabled=True; A.db.session.commit()
check("disabled setting stops alerts", res["sent"]==0)
check("admin alerts page renders", ca.get("/admin/alerts").status_code==200)

print("\n== Audit viewer")
page=ca.get("/admin/audit").get_data(as_text=True); check("audit page shows events", "share_create" in page and "create" in page)
check("filter by action", "share_create" in ca.get("/admin/audit?action=share_create").get_data(as_text=True))
csvr=ca.get("/admin/audit?format=csv"); check("CSV export works", csvr.mimetype=="text/csv" and b"time_utc" in csvr.data)
with A.app.test_request_context(): A.log_audit("test","x",1,details="=HYPERLINK(\"http://evil\")")
check("CSV neutralises formula injection", b"'=HYPERLINK" in ca.get("/admin/audit?format=csv").data)
check("date filter doesn't crash", ca.get("/admin/audit?from=2020-01-01&to=2099-01-01&q=Created").status_code==200)

print("\n== Backups")
r=post(ca,"/admin/backups",{"passphrase":"short","passphrase2":"short"}); check("short passphrase refused", not os.path.isdir(BK) or not backup.list_backups(BK))
r=post(ca,"/admin/backups",{"passphrase":"correct horse battery","passphrase2":"nope nope nope nope"}); check("mismatched passphrase refused", not backup.list_backups(BK))
r=post(ca,"/admin/backups",{"passphrase":"correct horse battery","passphrase2":"correct horse battery"})
bl=backup.list_backups(BK); check("encrypted backup created", len(bl)==1 and bl[0]["encrypted"])
name=bl[0]["name"]
check("backup list page renders", name.encode() in ca.get("/admin/backups").data)
dl=ca.get(f"/admin/backups/{name}/download"); check("download works & is encrypted", dl.status_code==200 and dl.data.startswith(b"CVBK1") and b"SQLite" not in dl.data[:200])
check("path traversal blocked", ca.get("/admin/backups/..%2f..%2fapp.py/download").status_code==404)
check("tech cannot download", ct.get(f"/admin/backups/{name}/download").status_code in (302,403))
bpath=f"{BK}/{name}"
try: backup.read_manifest(bpath,"wrong passphrase"); check("wrong passphrase rejected",False)
except backup.BackupError: check("wrong passphrase rejected",True)
m=backup.read_manifest(bpath,"correct horse battery"); check("manifest readable with passphrase", m["format"]==1 and m["encrypted"])
raw=bytearray(open(bpath,"rb").read()); raw[200]^=1; open(TMP + "/tampered.cvbak","wb").write(raw)
try: backup.read_manifest(TMP + "/tampered.cvbak","correct horse battery"); check("tampering detected",False)
except backup.BackupError: check("tampering detected",True)
# restore into scratch locations and open the DB
import sqlite3
shutil.rmtree(RT, ignore_errors=True); os.makedirs(RT)
mf,w=backup.restore_backup(bpath,RT + "/coresight.db",RT + "/uploads","correct horse battery",A.app.config["VAULT_KEY"] or A.app.config["SECRET_KEY"])
c=sqlite3.connect(RT + "/coresight.db"); n=c.execute("select count(*) from password").fetchone()[0]; recs=c.execute("select count(*) from custom_record").fetchone()[0]; c.close()
check("restore yields working DB with data", n>=2 and recs>=1 and not w, f"{n} {recs} {w}")
mf,w=backup.restore_backup(bpath,RT + "/coresight.db",RT + "/uploads","correct horse battery","DIFFERENT-KEY")
check("restore warns on key mismatch", any("VAULT_KEY" in x for x in w))
check("old data kept aside on restore", any(".pre-restore-" in f for f in os.listdir(RT)))
r=post(ca,"/admin/backups",{"unencrypted":"1"}); check("unencrypted backup possible when explicitly chosen", any(not b["encrypted"] for b in backup.list_backups(BK)))
for b in backup.list_backups(BK):
    post(ca,f"/admin/backups/{b['name']}/delete")
check("backups deletable", not backup.list_backups(BK))

print("\n== Dark theme / misc")
page=ca.get("/expiring").get_data(as_text=True)
check("theme attribute + toggle present", 'data-bs-theme' in page and "cycleTheme" in page)
check("open redirect blocked", ca.get(f"/org/{ids['o1']}?next=https://evil.com").status_code==200 and ca.get(f"/org/{ids['o1']}?next=//evil.com").status_code==200)
check("safe ?next still works", ca.get(f"/org/{ids['o1']}?next=/expiring").status_code==302)

print("\n== Playbook with custom records + related")
r=post(ca,f"/orgs/{ids['o1']}/export",{"sections":["overview","records","passwords","assets"],"credentials":"full","confirm_password":"admin","pdf_password":"Another-Long-Pdf-Pw1"})
check("export responds", r.status_code==200 and r.mimetype=="application/pdf", f"{r.status_code}")
if r.status_code==200:
    from pypdf import PdfReader
    rd=PdfReader(io.BytesIO(r.data)); rd.decrypt("Another-Long-Pdf-Pw1"); txt="\n".join(p.extract_text() for p in rd.pages)
    check("PDF has custom record + decrypted licence key", "M365 licence v2" in txt and "AAAA-BBBB" in txt)
    check("PDF shows related link and warranty", "Related" in txt and "Firewall" in txt and "Warranty" in txt)
r=post(ca,f"/orgs/{ids['o1']}/export",{"sections":["records"],"credentials":"list"})
rd=PdfReader(io.BytesIO(r.data)); txt="\n".join(p.extract_text() for p in rd.pages)
check("licence key omitted when passwords excluded", "AAAA-BBBB" not in txt and "(omitted)" in txt)

print("\n== Read-only users don't see write buttons")
with A.app.app_context():
    a1=A.Asset.query.filter_by(org_id=ids["o1"]).first(); d1=A.Domain.query.filter_by(org_id=ids["o1"]).first()
    dp=A.DocPage(org_id=ids["o1"],title="RO doc",body_html="<p>x</p>"); A.db.session.add(dp); A.db.session.commit()
    ro_pages={"passwords list":"/passwords","password view":f"/passwords/{ids['pw']}/view","assets":"/assets",
              "asset view":f"/assets/{a1.id}/view","domain view":f"/domains/{d1.id}","docs":"/docs","doc":f"/docs/page/{dp.id}",
              "org":f"/org/{ids['o1']}","orgs":"/orgs","contacts":"/contacts","sites":"/sites","network":"/network"}
WRITE_MARKERS=["/new\"","/edit\"","/delete\"","/import\"","Generate link","/rollback","/revoke","Export playbook","Save Assignment","docs/upload","folder/new"]
bad={}
for label,url in ro_pages.items():
    r=cr.get(url, follow_redirects=True); h=r.get_data(as_text=True)
    hits=[m for m in WRITE_MARKERS if m in h]
    if r.status_code!=200 or hits: bad[label]=(r.status_code,hits)
check("read-only pages render without write buttons", not bad, str(bad))
h=cr.get(f"/passwords/{ids['pw']}/view").get_data(as_text=True)
check("read-only still gets the reveal button", "revealSecrets" in h and "read-only" in h)
check("read-only has no password edit link", f"/passwords/{ids['pw']}\"" not in h)
h=ct.get(f"/passwords/{ids['pw']}/view").get_data(as_text=True)
check("tech still sees edit/share/delete", all(m in h for m in [f"/passwords/{ids['pw']}\"","Generate link","/delete\""]))
check("tech still sees New Asset + docs upload", "New Asset" in ct.get("/assets").get_data(as_text=True) and "docs/upload" in ct.get("/docs").get_data(as_text=True))

print("\n== Expiring-soon badge")
h=ca.get("/orgs").get_data(as_text=True)
m=re.search(r'Expiring soon<span class="badge[^"]*"[^>]*>(\d+)</span>',h)
check("sidebar shows expiring count", m is not None and int(m.group(1))>=2, m and m.group(1))
before=int(m.group(1)) if m else 0
check("home page shows summary card + per-client pill", "due in the next 30 days" in h and "expiring</span>" in h)
with A.app.app_context():
    A.db.session.add(A.Domain(org_id=ids["o1"],domain_name="old-expired.com",expires_on=date.today()-timedelta(days=3))); A.db.session.commit()
h=ca.get("/orgs").get_data(as_text=True)
m=re.search(r'Expiring soon<span class="badge ([^"]*)"[^>]*>(\d+)</span>',h)
check("badge updates straight after a change and turns red when something has expired",
      m is not None and int(m.group(2))==before+1 and "danger" in m.group(1) and "already expired" in h)
check("read-only users see the badge too", "Expiring soon<span class=\"badge" in cr.get("/orgs").get_data(as_text=True))
check("no badge on the public login page", "Expiring soon" not in A.app.test_client().get("/login").get_data(as_text=True))

print("\n== Welcome email uses a one-time set-password link")
sent=[]
real_send=A.send_email
A.send_email=lambda to,subj,body,*a,**k: sent.append((to,subj,body))
r=post(ca,"/admin/users/new",{"email":"new1@x.com","password":"","role":"tech"})
check("user created without typing a password", r.status_code==302 and len(sent)==1)
body=sent[-1][2] if sent else ""
lm=re.search(r"(/reset-password/\S+)",body)
check("welcome email has a set-password link and no password", lm is not None and "Temporary Password" not in body)
anon=A.app.test_client()
h=anon.get(lm.group(1)).get_data(as_text=True) if lm else ""
check("link opens a 'Choose your password' page", "Choose your password" in h and "new1@x.com" in h)
def anon_post(c,url,data):
    t=re.search(r'name="csrf_token" value="([^"]+)"',c.get(url).get_data(as_text=True))
    d=dict(data); d["csrf_token"]=t.group(1) if t else ""; return c.post(url,data=d)
r=anon_post(anon,lm.group(1),{"password":"Brand-New-Pass1","confirm_password":"Brand-New-Pass1"})
with A.app.app_context():
    u=A.User.query.filter_by(email="new1@x.com").first()
    check("password set through the link", u.check_password("Brand-New-Pass1") and not u.must_change_password)
r=anon.get(lm.group(1),follow_redirects=True).get_data(as_text=True)
check("welcome link can't be used twice", "already been used" in r)
sent.clear()
r=post(ca,"/admin/users/new",{"email":"new2@x.com","password":"Typed-Temp-Pass9","role":"readonly"})
check("admin-typed password is NOT put in the email", sent and "Typed-Temp-Pass9" not in sent[-1][2] and "separately" in sent[-1][2])
with A.app.app_context():
    check("admin-typed password still forces a change at first login", A.User.query.filter_by(email="new2@x.com").first().must_change_password)
def boom(*a,**k): raise RuntimeError("SMTP settings are not configured")
A.send_email=boom
r=post(ca,"/admin/users/new",{"email":"new3@x.com","password":"","role":"tech"})
h=r.get_data(as_text=True)
check("if email fails, the admin is shown the link once to pass on", r.status_code==200 and "/reset-password/" in h and "new3@x.com" in h)
A.send_email=lambda to,subj,body,*a,**k: sent.append((to,subj,body)); sent.clear()
r=anon_post(anon,"/forgot-password",{"email":"new1@x.com"})
fl=re.search(r"(/reset-password/\S+)",sent[-1][2]).group(1) if sent else "/reset-password/x"
anon_post(anon,fl,{"password":"Second-Pass-22a","confirm_password":"Second-Pass-22a"})
r=anon.get(fl,follow_redirects=True).get_data(as_text=True)
check("forgot-password links are single-use too", "already been used" in r)
check("tampered link rejected", "already been used" in anon.get(fl[:-3]+"abc",follow_redirects=True).get_data(as_text=True))
A.send_email=real_send

print("\n== Vault key rotation (rotate_key.py)")
import subprocess, sqlite3
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with A.app.app_context():
    A.db.session.add(A.Password(org_id=ids["o1"],name="Legacy plain",username_plain="olduser",password_plain="plain-Legacy-1"))
    A.db.session.commit()
    src=A.db.engine.url.database
    A.db.engine.dispose()
rdb=TMP+"/rot.db"; shutil.copy(src,rdb)
envf=TMP+"/rot.env"; open(envf,"w").write("SECRET_KEY=test-secret-key-123\nVAULT_KEY=\nOTHER_SETTING=keep-me\n")
base_env=dict(os.environ, DATABASE_URL="sqlite:///"+rdb, BACKUP_DIR=TMP+"/rotbk", UPLOAD_DIR=TMP+"/uploads",
              SECRET_KEY="test-secret-key-123", VAULT_KEY="")
READ=("import app as A\nwith A.app.app_context():\n"
      " p=A.Password.query.filter_by(name='Firewall').first(); l=A.Password.query.filter_by(name='Legacy plain').first()\n"
      " r=[x for x in A.CustomRecord.query.all() if 'AAAA-BBBB' in str([A.decrypt_secret(v) for v in x.data.values() if isinstance(v,str)])]\n"
      " print('FW='+A.decrypt_secret(p.password_plain), 'LEG='+A.decrypt_secret(l.password_plain), 'LEGRAW='+l.password_plain[:4], 'REC=%d'%len(r))")
def run(args, env):
    return subprocess.run([sys.executable]+args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
r=run(["rotate_key.py","--yes","--env-file",envf], base_env)
check("rotation completes", r.returncode==0 and "Done" in r.stdout, r.stdout[-300:]+r.stderr[-300:])
newkey=[l.split("=",1)[1] for l in open(envf).read().splitlines() if l.startswith("VAULT_KEY=")][0]
check(".env gets the new key and keeps other settings", len(newkey)==44 and "OTHER_SETTING=keep-me" in open(envf).read())
check("old .env kept for restoring older backups", any(f.startswith("rot.env.before-rotation-") for f in os.listdir(TMP)))
check("backup taken before rotating", os.path.isdir(TMP+"/rotbk") and len(os.listdir(TMP+"/rotbk"))>=1)
out=run(["-c",READ], dict(base_env, VAULT_KEY=newkey)).stdout
check("secrets readable with the new key", "FW=fw-Secret!1" in out and "REC=1" in out, out)
check("legacy plain-text password got encrypted", "LEG=plain-Legacy-1" in out and "LEGRAW=enc:" in out, out)
out=run(["-c",READ], base_env).stdout
check("old key no longer decrypts", "FW=fw-Secret!1" not in out, out)
c=sqlite3.connect(rdb); c.execute("UPDATE password SET notes='enc:not-a-real-token' WHERE name='Firewall'"); c.commit()
before=c.execute("SELECT password_plain FROM password WHERE name='Firewall'").fetchone()[0]; c.close()
r=run(["rotate_key.py","--yes","--no-backup","--env-file",envf], dict(base_env, VAULT_KEY=newkey))
c=sqlite3.connect(rdb); after=c.execute("SELECT password_plain FROM password WHERE name='Firewall'").fetchone()[0]; c.close()
check("stops and changes nothing if any secret is unreadable", r.returncode==2 and before==after and
      [l for l in open(envf).read().splitlines() if l.startswith("VAULT_KEY=")][0]=="VAULT_KEY="+newkey, r.stdout[-200:])

print("\n== Password generator, folders/tags, rotation reminders")
r=post(ct,"/passwords/new",{"name":"Core switch","username":"admin","password":"Sw1tch-Pass!","folder":"  Network ",
                            "tags":"admin, switch ,ADMIN,  core  ","rotate_days":"90"})
with A.app.app_context():
    sw=A.Password.query.filter_by(name="Core switch").first()
    check("folder/tags/rotation saved, tags tidied", sw and sw.folder=="Network" and sw.tags=="admin, switch, core" and sw.rotate_days==90, sw and (sw.folder,sw.tags))
    check("new password starts the rotation clock", sw.password_changed_at is not None and sw.rotation_due_on==date.today()+timedelta(days=90))
    sw_id=sw.id; changed0=sw.password_changed_at
h=ct.get(f"/passwords/{sw_id}").get_data(as_text=True)
check("form has generator, folder suggestions, tag chips and rotation", "generatePassword()" in h and 'list="folderOptions"' in h
      and "addTag(" in h and 'name="rotate_days"' in h and "crypto.getRandomValues" in h)
post(ct,f"/passwords/{sw_id}",{"name":"Core switch","username":"admin","password":"Sw1tch-Pass!","folder":"Network","tags":"admin","rotate_days":"90"})
with A.app.app_context():
    check("editing other fields doesn't reset the rotation clock", A.db.session.get(A.Password,sw_id).password_changed_at==changed0)
post(ct,f"/passwords/{sw_id}",{"name":"Core switch","username":"admin","password":"New-Sw1tch-Pass!","folder":"Network","tags":"admin","rotate_days":"90"})
with A.app.app_context():
    check("changing the password resets the rotation clock", A.db.session.get(A.Password,sw_id).password_changed_at>changed0)

# 2FA secret must survive edits (it used to be wiped on every save)
with A.app.app_context():
    p2=A.Password(org_id=ids["o1"],name="M365 admin",password_plain=A.encrypt_secret("x"),otp_secret=A.encrypt_secret("JBSWY3DPEHPK3PXP"))
    A.db.session.add(p2); A.db.session.commit(); p2id=p2.id
check("edit form shows 'OTP Configured'", "OTP Configured" in ct.get(f"/passwords/{p2id}").get_data(as_text=True))
post(ct,f"/passwords/{p2id}",{"name":"M365 admin (renamed)","password":"x","otp_secret":""})
with A.app.app_context():
    check("2FA secret kept when the box is left blank", A.decrypt_secret(A.db.session.get(A.Password,p2id).otp_secret)=="JBSWY3DPEHPK3PXP")
post(ct,f"/passwords/{p2id}",{"name":"M365 admin","password":"x","otp_secret":"abcd efgh ijkl mnop"})
with A.app.app_context():
    check("2FA secret replaced when a new one is typed", A.decrypt_secret(A.db.session.get(A.Password,p2id).otp_secret)=="ABCDEFGHIJKLMNOP")
post(ct,f"/passwords/{p2id}",{"name":"M365 admin","password":"x","otp_secret":"","clear_otp":"1"})
with A.app.app_context():
    check("'Remove OTP secret' tickbox works", A.db.session.get(A.Password,p2id).otp_secret is None)

with A.app.app_context():
    old=A.Password(org_id=ids["o1"],name="Old router",password_plain=A.encrypt_secret("r"),folder="Network",tags="router",
                   rotate_days=90,password_changed_at=datetime.utcnow()-timedelta(days=100))
    A.db.session.add(old); A.db.session.commit(); old_id=old.id
h=ca.get("/passwords").get_data(as_text=True)
check("list groups by folder (No folder last)", "Network" in h and "No folder" in h and h.index(">Network")<h.index("No folder"))
check("list shows tag chips and rotation status", "Overdue 10d" in h and "router" in h)
h=ca.get("/passwords?tag=ROUTER").get_data(as_text=True)
check("tag filter (case-insensitive)", "Old router" in h and "Firewall" not in h)
h=ca.get("/passwords?folder=Network").get_data(as_text=True)
check("folder filter", "Core switch" in h and "Firewall" not in h)
h=ca.get("/passwords?folder=").get_data(as_text=True)
check("'No folder' filter", "Firewall" in h and "Core switch" not in h)
check("search matches tags", "Old router" in ca.get("/passwords?q=route").get_data(as_text=True))
j=ca.get("/search/global?q=router").get_data(as_text=True)
check("global search finds passwords by tag", "Old router" in j)
h=ca.get("/expiring").get_data(as_text=True)
check("overdue rotation on the Expiring page", "Password rotation" in h and "Old router" in h and "Overdue 10 day(s)" in h)
with A.app.app_context():
    items=[i for i in ops.collect_expiring() if i["kind"]=="Password rotation" and i["name"]=="Old router"]
    check("rotation item feeds the badge + email", items and items[0]["days"]==-10 and "change overdue by 10 day(s)" in ops._when(items[0]))
h=ca.get(f"/passwords/{old_id}/view").get_data(as_text=True)
check("detail page shows folder, tags and overdue notice", "Network" in h and "router" in h and "Password change overdue by 10 day(s)" in h)
csv_data="name,password,folder,tags\nImported AP,ap-Pass-1,Wi-Fi,\"wifi, ap\"\n"
tk=token(ct)
r=ct.post("/passwords/import",data={"csrf_token":tk,"file":(io.BytesIO(csv_data.encode()),"pw.csv")},content_type="multipart/form-data")
with A.app.app_context():
    ap=A.Password.query.filter_by(name="Imported AP").first()
    check("CSV import accepts folder + tags", ap and ap.folder=="Wi-Fi" and ap.tags=="wifi, ap" and ap.password_changed_at is not None)
h=cr.get("/passwords").get_data(as_text=True)
check("read-only sees folders/tags but no Add/Import", "Network" in h and "/passwords/new" not in h and "/passwords/import" not in h)

print("\n== Empty fields don't turn into the word 'None'")
with A.app.app_context():
    e=A.Password(org_id=ids["o1"],name="No URL pw",password_plain=A.encrypt_secret("x")); A.db.session.add(e)
    ea=A.Asset(org_id=ids["o1"],device_name="Bare PC"); A.db.session.add(ea); A.db.session.commit(); eid,eaid=e.id,ea.id
h=ct.get(f"/passwords/{eid}").get_data(as_text=True)
check("password form shows empty boxes, not 'None'", 'value="None"' not in h and ">None</textarea>" not in h)
f={k:v for k,v in re.findall(r'name="(name|url|username|password|notes)"[^>]*value="([^"]*)"',h)}
post(ct,f"/passwords/{eid}",{"name":"No URL pw","url":f.get("url",""),"username":f.get("username",""),"password":"x","notes":""})
with A.app.app_context():
    e=A.db.session.get(A.Password,eid); check("saving keeps URL/notes empty", e.url is None and e.notes is None, (e.url,e.notes))
h=ct.get(f"/assets/{eaid}/edit").get_data(as_text=True)
check("other edit forms (assets) fixed too", 'value="None"' not in h and ">None</textarea>" not in h)

print(f"\n{ok_n} passed, {fail_n} failed")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if fail_n else 0)
