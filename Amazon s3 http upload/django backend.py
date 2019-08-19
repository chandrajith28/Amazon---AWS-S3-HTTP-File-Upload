from datetime import datetime,timedelta
import base64
import hmac
import hashlib




def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def hexsign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning


def backend_authenticate(request):
    currtime=datetime.now()
    tdel=currtime+timedelta(minutes=10)
    tex=str(tdel)
    currex=str(currtime)
    print("tex:"+tex)
    yyyy=str(currex[:4])
    #print(yyyy)
    mm=str(currex[5:7])
    #print(mm)
    dd=str(currex[8:10])
    hh=str(currex[11:13])
    min=str(currex[14:16])
    ss=str(currex[17:19])
    #print(dd)
    date=yyyy+mm+dd+'T'+hh+min+ss+'Z'
    d=yyyy+mm+dd
    print("date:"+d)
    print("d[0]=",d[0])
    #print(hh)
    #print(min)
    #print(ss)

    #print("date:"+date)
    texp=tex[0:10]+'T'+tex[11:19]+'Z'
    print("texp=",texp)
    print("texp[0]=",texp[0])
    Postpolicy = {
    "expiration" : texp,
    "conditions" : [
    {"bucket" : "<enter your S3 bucket name here>"},#S3 bucket name
    {"acl" : "public-read"},
    ["starts-with","$key",""],
    {"x-amz-date" : date},
    #{"success_action_redirect": "https://www.google.com/" },
    {"success_action_redirect": '<enter the url to be redirected to on succesful upload>' },
    {"x-amz-algorithm" : "AWS4-HMAC-SHA256"},
    {"x-amz-credential" : "<enter the aws credentials to be used to upload the file into your S3 bucket"},
    {"x-amz-server-side-encryption" : "AES256"}
    ]}
    encodedPostpolicy = str(Postpolicy).encode("utf-8")
    B64Postpolicy = base64.b64encode(encodedPostpolicy)
    policy=B64Postpolicy.decode()
    signingkey = getSignatureKey('<enter your secret access key here>',d,"<aws region here>","<aws service here,for s3 upload:s3>")
    signature = hexsign(signingkey,policy)

    my_dict = {
    "date" : date,
    "credentials" : Postpolicy["conditions"][6]['x-amz-credential'],
    "policy" : policy,
    "signature" : signature,
    "URL" : Postpolicy["conditions"][4]['success_action_redirect']
    }
    print("credentials=",my_dict['credentials'])
    print("credentials[0]=",my_dict['credentials'][0])
    print("amz-date=",date)
    print("success-redirect=",Postpolicy["conditions"][4]['success_action_redirect'])
    print("amz-date[0]=",date[0])
    print("expiration=",Postpolicy['expiration'])
    #print(B64Postpolicy)
    return render(request,'file_upload.html',context = my_dict )
