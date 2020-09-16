/**

    API for DNS Made Easy
    Ported to the D Programming Language (2015) by Laeeth Isharc and Kaleidic Associates

    Requires Phobos from DMD 2.069 for HMAC function
    (or backport the relevant source code - you're on your own here)

    Alpha and not well-tested, so use at your own risk.
*/

module kaleidic.api.dnsmadeeasyv2;
/+
not yet finished

import std.json;
import std.net.curl;
import std.datetime;
import std.stdio;
import std.exception:enforce;
import std.format;
import std.array:appender,array;
import kprop.helper.prettyjson;
import std.digest.hmac;
import std.digest;
import std.digest.sha;
import std.string:representation;
import kprop.api.dnsmadeeasy.auth;

string[] weekDays=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
string[] monthStrings= ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];


string joinUrl(string url, string endpoint)
{
    enforce(url.length>0, "broken url");
    if (url[$-1]=='/')
        url=url[0..$-1];
    return url~"/"~endpoint;
}


string toHttpString(SysTime dt)
{
    // Sat, 12 Feb 2011 20:59:04 GMT
    return format("%s, %02d %s %s %02d:%02d:%02d %s",
        weekDays[dt.dayOfWeek.to!size_t],
        dt.day,
        monthStrings[dt.month-1],
        dt.year,
        dt.hour,
        dt.minute,
        dt.second,
        dt.timezone.dstName);
}

struct HashResult
{
    string date;
    string value;
}
struct DnsMadeEasy
{
    string api;
    string secret;
    string endPoint="https://api.dnsmadeeasy.com/V2.0/";
    // sandbox string endPoint="https://api.sandbox.dnsmadeeasy.com/V2.0/";

    // dns.:Sat, 12 Feb 2011 20:59:04 GMT
    this(string api, string secret, string endPoint=null)
    {
        this.api=api;
        this.secret=secret;
        if(endPoint.length>0)
            this.endPoint=endPoint;
    }


    //return strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime());


    auto createHash()
    {
        auto date=Clock.currTime
                .toHttpString;
        return HashResult(date,
                date.representation
                .hmac!SHA1(this.secret.representation)
                .toHexString!(LetterCase.lower).dup);
    }
}
struct EasyDomainID
{
    int value;
    alias value this;
}
struct EasyResponse
{
    long id;
    long requestLimit;
    long requestsRemaining;
}

struct EasyDomain
{
    string name;                // name
    EasyDomainID id;
    int pendingActionID;
    int folderID;
    DateTime created;
    DateTime updated;

    string[] nameServers;       // nameServer
    bool gtdEnabled;             // gtdEnabled
}

enum EasyDomainRecordType
{
    A,
    AAAA,
    CNAME,
    HTTPRED,
    MX,
    NS,
    PTR,
    SRV,
    TXT
}

enum EasyDirectorLocation
{
    Default,
    US_East,
    US_West,
    Europe
}
struct EasyDomainRecord
{
    DomainID id;
    string name;
    EasyDomainRecordType type;
    string data;
    int ttl;
    EasyDirectorLocation gtdLocation;
    string dynamicPassword;             // for dynamic DNS
    EasyDomainRecordHttpRed httpRed;
    string[] nameServers;
    bool gtdEnabled;

    EasyDomainRecordType type;
    union RecordUnion
    {
        EasyDomainRecordSOA soa;
        EasyDomainRecordTemplate templ;
        EasyDomainRecordVanity vanity;
        Easy
    }
}
enum EasyDomainRecordType
{
    soa,
    template,
    vanity,
    transfer,
    folder
}
struct EasyDomainRecordSOA
{
    int soaID;
}
struct EasyDomainRecordTemplate
{
    int templateID;
}
struct EasyDomainRecordVanity
{
    int vanityID;
}
struct EasyDomainRecordTransfer
{
    int transferAclId;
}
struct EasyDomainRecordFolder
{
    int folderID;
}

soaID numeric The ID of a custom SOA record
templateId numeric The ID of a template applied to the domain
vanityId numeric The ID of a vanity DNS configuration
transferAclId numeric The ID of an applied transfer ACL
folderId numeric The ID of a domain folder
updated numeric The number of seconds since the domain
was last updated in Epoch time
created numeric The number of seconds since the domain
was last created in Epoch time
axfrServer List of Strings The list of servers defined in an applied
AXFR ACL.
delegateNameServers List of Strings The name servers assigned to the domain
at the registrar
struct EasyDomainRecordHttpRed
{
    string description;
    string keywords;
    string title;
    string redirectType;
    bool hardLink;
}

struct EasyDomainRecordSecondary
{
    string name;
    string[] ipMaster;
}

auto restConnect(DnsMadeEasy dns, string resource, HTTP.Method method, JSONValue params=JSONValue(null))
{
    enforce(dns.api.length>0 && dns.secret.length>0,"must provide API and token first");
    auto url=dns.endPoint.joinUrl(resource);
    auto client=HTTP(url);
    auto hash=dns.createHash;
    client.addRequestHeader("x-dnsme-apiKey",dns.api);
    client.addRequestHeader("x-dnsme-requestDate",hash.date);
    client.addRequestHeader("x-dnsme-hmac",hash.value);

    auto response=appender!(ubyte[]);
    client.method=method;
    client.setPostData(cast(void[])params.toString,"application/json");

    client.onReceive = (ubyte[] data)
    {
        response.put(data);
        return data.length;
    };
    client.perform();                 // rely on curl to throw exceptions on 204, >=500
    return parseJSON(cast(string)response.data);
}

// response fields
// x-dnsme-requestId - unique identifier for API call
// x-dnsme-requestLimit
// x-dnsmerequestsRemaining


auto listDomains(DnsMadeEasy dns, bool secondary=false)
{
    auto domains=appender!(string[]);
    auto response= dns.restConnect(secondary?"dns/secondary":"dns/managed", HTTP.Method.get );
    foreach(domain;response["list"].array)
        domains.put(domain.str);
    return domains.data;
}

//!!!!! Following function deletes all of your domains. Use with caution.

auto deleteAllDomains(DnsMadeEasy dns, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary":"dns/managed", HTTP.Method.del);
}

//  Possible fields for updateDomains
//          global Traffic Director
//      • Applied Template (numeric ID)
//      • Vanity NS Config (numeric ID)
//      • Custom SOA Record (numeric ID)
//      • Zone Transfer (numeric ID)
//      • Folder (numeric ID)

auto getDomainRecord(DnsMadeEasy dns, DomainID id, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ id.value.to!string, HTTP.Method.get );
}
auto updateDomains(DnsMadeEasy dns, EasyDomainID[] ids, string[string] fields, bool secondary=false)
{
    fields["ids"]=ids.map!(a=>a.value);
    return dns.restConnect(secondary?"dns/secondary":"dns/managed" , HTTP.Method.put, data);
}


auto findDomain(DnsMadeEasy dns, string domainName)
{
    return dns.restConnect("dns/managed/name?domainname="~domainName, HTTP.Method.get );
}

auto deleteDomain(DnsMadeEasy dns,string domain, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ domain, HTTP.Method.del);
}

auto createDomains(DnsMadeEasy dns, string[] domains, bool secondary=false)
{
    JSONValue data;
    data["names"]=domains;
    return dns.restConnect(secondary?"dns/secondary":"dns/managed", HTTP.Method.post,data);
}

auto deleteDomains(DnsMadeEasy dns, string[] domains, bool secondary=false)
{
    JSONValue data;
    data["names"]=domains;
    return dns.restConnect(secondary?"dns/secondary":"dns/managed",HTTP.Method.del, data);
}


// for getRecords: the following are URL parameters that may be
// added to determine the data returned:
// • type – Record type. Values: A, AAAA, CNAME, HTTPRED, MX, NS, PTR, SRV, TXT
//  • rows – Number of rows returns
//  • page – The page number of records, based on the number of rows returned
auto getRecords(DnsMadeEasy dns, EasyDomainId domain, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary":"dns/managed/" ~ domain.value.to!string ~ "/records", HTTP.Method.get);
}

auto createRecords(DnsMadeEasy dns, string domain, JSONValue data, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ domain ~ "/records", HTTP.Method.post, data);
}

auto updateRecords(DnsMadeEasy dns, EasyDomainId domain, JSONValue data, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ domain ~ "/records", HTTP.Method.put, data);
}

auto getRecord(DnsMadeEasy dns,EasyDomainID domain, string id, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ domain ~ "/records/" ~ id, HTTP.Method.get);
}

auto deleteRecords(DnsMadeEasy dns,EasyDomainID domain, string[] ids, bool secondary=false)
{
    JSONValue data;
    data["ids"]=ids;
    return dns.restConnect(secondary?"dns/secondary/":"dns/managed/" ~ domain ~ "/records/" ~ id, HTTP.Method.del,data);
}

auto updateRecord(DnsMadeEasy dns,EasyDomainID domain, string id, JSONValue data, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary":"dns/managed/" ~
         domain.id.to!string ~ "/records/" ~ id, HTTP.Method.put, data);
}
auto deleteRecord(DnsMadeEasy dns,EasyDomainID domain, string id, JSONValue data, bool secondary=false)
{
    return dns.restConnect(secondary?"dns/secondary":"dns/managed/" ~
        domain.id.to!string ~ "/records/" ~ id, HTTP.Method.del, data);
}

auto getSoa(DnsMadeEasy dns)
{
    return dns.restConnect("dns/soa/",HTTP.Method.get);
}
auto getSoa(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/soa/"~domain.id.to!string,HTTP.Method.get);
}
auto updateSoa(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/soa/"~domain.id.to!string,HTTP.Method.put,data);
}
auto createSoa(DnsMadeEasy dns, EasyDomainID domain,JSONValue data)
{
    return dns.restConnect("dns/soa/"~domain.id.to!string,HTTP.Method.post,data);
}
auto deleteSoa(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/soa/"~domain.id.to!string,HTTP.Method.del);
}

auto getVanity(DnsMadeEasy dns)
{
    return dns.restConnect("dns/vanity",HTTP.Method.get);
}
auto getVanity(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/vanity/"~domain.id.to!string,HTTP.Method.get);
}
auto updateVanity(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/vanity/"~domain.id.to!string,HTTP.Method.put,data);
}
auto createVanity(DnsMadeEasy dns, EasyDomainID domain,JSONValue data)
{
    return dns.restConnect("dns/vanity/"~domain.id.to!string,HTTP.Method.post,data);
}
auto deleteVanity(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/vanity/"~domain.id.to!string,HTTP.Method.del);
}

auto getTransfers(DnsMadeEasy dns)
{
    return dns.restConnect("dns/transferAclId",HTTP.Method.get);
}
auto getTransfer(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/transferAcl/"~domain.id.to!string,HTTP.Method.get);
}
auto updateTransfer(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns/transferAcl/"~domain.id.to!string,HTTP.Method.put,data);
}
auto createTransfer(DnsMadeEasy dns, EasyDomainID domain,JSONValue data)
{
    return dns.restConnect(secondary?"":"dns/transferAcl/"~domain.id.to!string,HTTP.Method.post,data);
}
auto deleteTransfer(DnsMadeEasy dns, EasyDomainID domain)
{
    return dns.restConnect("dns.transferAcl/"~domain.id.to!string,HTTP.Method.del);
}


auto getFolders(DnsMadeEasy dns, bool secondary=false)
{
    return dns.restConnect(secondary?"":"security/folder/",HTTP.Method.get);
}
auto updateFolder(DnsMadeEasy dns, JSONValue data, bool secondary=false)
{
    return dns.restConnect(secondary?"":"security/folder/",HTTP.Method.put,data);
}
auto createFolder(DnsMadeEasy dns, JSONValue data)
{
    return dns.restConnect(secondary?"":"security/folder/",HTTP.Method.post,data);
}
auto deleteFolder(DnsMadeEasy dns, JSONValue data)
{
    return dns.restConnect("security/folder/",HTTP.Method.del,data);
}
auto getFailover(DnsMadeEasy dns, EasyDomainID domain, bool secondary=false)
{
    return dns.restConnect(secondary?"":"monitor/"~domain.id.to!string,HTTP.Method.get);
}
auto updateFailover(DnsMadeEasy dns, EasyDomainID domain, JSONValue records, bool secondary=false)
{
    return dns.restConnect(secondary?"":"monitor/"~domain.id.to!string,HTTP.Method.put,records);
}
auto getUsage(DnsMadeEasy dns)
{
    return dns.restConnect("usageApi/queriesApi");
}

auto getUsage(DnsMadeEasy dns, int year, int month)
{
    return dns.restConnect("usageApi/queriesApi/"~year.to!string~"/"~month.to!string);
}

auto getUsage(DnsMadeEasy dns, EasyDomainID domain, int year, int month, bool secondary=false)
{
    return dns.restConnect("usageApi/queriesApi/"~year.to!string~"/"~month.to!string~
        (secondary?"/secondary/":"/managed/")~domain.id.to!string);
}


void main(string[] args)
{
    auto dns = DnsMadeEasy(DnsMadeEasyAPI, DnsMadeEasySecret);
    writefln("hash: %s",dns.createHash);
    // listDomains: returns a list of all domains
    writefln("\nList all domains: \n");
    auto domains = dns.listDomains;
    foreach(d;domains)
        writefln(d);

    // listRecords for a single domain
    writefln("\nList records for a single domain:");
    auto records = dns.getRecords("kaleidicassociates.com");
    foreach(entry;records.array)
    {
        writefln("");
        foreach(key, value;entry.object)
            writefln("%s : %s",key,value.to!string);
    }

    // getDomain for a single domain
    writefln("\nGet general info about a single domain: \n");
    auto domainInfo = dns.getDomain("kaleidicassociates.com");
    writefln("%s",domainInfo.prettyPrint);


    // delete a domain

    writefln("Delete domain: \n");
    auto result = dns.deleteDomain("testdomain2.com");
    if ("status" in result)
        writefln("status: %s",result["status"]);
    else
        writefln("* failed to delete: result was - %s",result.prettyPrint);


/**
    Following is not well tested

    // add a domain

    writefln("\nAdd domain");
    auto content = dns.addDomain("testdomain5.com");
    writefln(content["name"].str ~ " added!");



    // add a single record to a domain

    writefln("\nAdd record to domain: \n");
    JSONValue data;
    data["name"]=args[1];
    data["type"]="A";
    data["data"]=args[2];
    data["gtdLocation"]="Default";
    data["ttl"]=1800;
    result = dns.addRecord("kaleidicassociates.com", data);
    writefln(result.prettyPrint);
    JSONValue record;
    record = dns.getRecordById("kaleidicassociates.com","6883496");
    writefln(record.prettyPrint);

    record = dns.deleteRecordById("test1.com", "6883496");

    data=JSONValue(null);
    data["name"]="";
    data["type"]="MX";
    data["data"]="10 mail";
    data["gtdLocation"]=["DEFAULT"];
    data["ttl"]=1800;
    record = dns.updateRecordById("testdomain1.com", "6883496", data);
    writefln(record.prettyPrint);
*/
}

+/
