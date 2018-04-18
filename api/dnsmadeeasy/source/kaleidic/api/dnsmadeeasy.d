/**

    API for DNS Made Easy
    Ported to the D Programming Language (2015) by Laeeth Isharc and Kaleidic Associates

    Requires Phobos from DMD 2.069 for HMAC function
    (or backport the relevant source code - you're on your own here)

    Alpha and not well-tested, so use at your own risk.
*/

///
module kaleidic.api.dnsmadeeasy;
import std.string;
import std.array:front;
import std.json;
import std.net.curl;
import std.datetime:SysTime,Clock;
import std.stdio;
import std.exception:enforce;
import std.format;
import std.array:appender,array;
//import kaleidic.helper.prettyjson;
import std.digest.hmac;
import std.digest.digest;
import std.digest.sha;
import std.string:representation;
//import kaleidic.auth;
import std.conv;

///
string[] weekDays=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
///
string[] monthStrings= ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

string randomPassword(int n)
{
	import std.algorithm : fill;
	import std.ascii : letters, digits;
	import std.conv : to;
	import std.random : randomCover, rndGen;
	import std.range : chain;
	auto asciiLetters = to!(dchar[])(letters);
	auto asciiDigits = to!(dchar[])(digits);

	dchar[] key;
	key.length = n;
	fill(key[], randomCover(chain(asciiLetters, asciiDigits), rndGen));
	return key.to!string;
}

///
string joinUrl(string url, string endpoint)
{
    enforce(url.length>0, "broken url");
    if (url[$-1]=='/')
        url=url[0..$-1];
    return url~"/"~endpoint;
}


/// Sat, 12 Feb 2011 20:59:04 GMT
string toHttpString(SysTime dt)
{
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

///
struct HashResult
{
    string date;
    string value;
}

///
struct DnsMadeEasy
{
    string api;
    string secret;
    string endPoint="http://api.dnsmadeeasy.com/V2.0/dns/";

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

///
struct EasyResponse
{
    long id;
    long requestLimit;
    long requestsRemaining;
}

///
struct EasyDomain
{
    string name;                // name
    string[] nameServers;       // nameServer
    bool gtdEnabled;             // gtdEnabled
}

///
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

///
enum EasyDirectorLocation
{
    Default,
    US_East,
    US_West,
    Europe
}

///
struct EasyDomainRecord
{
    int id;
    string name;
    EasyDomainRecordType type;
    string data;
    int ttl;
    EasyDirectorLocation gtdLocation;
    string dynamicPassword;             /// for dynamic DNS
    EasyDomainRecordHttpRed httpRed;
}

///
struct EasyDomainRecordHttpRed
{
    string description;
    string keywords;
    string title;
    string redirectType;
    bool hardLink;
}

///
struct EasyDomainRecordSecondary
{
    string name;
    string[] ipMaster;
}

///
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
    debug writeln(cast(string)response.data);
    return parseJSON(cast(string)response.data);
}

/// listDomains
long[string] listDomains(DnsMadeEasy dns)
{
	long[string] ret;
    auto domains=appender!(string[]);
    auto response = dns.restConnect("managed", HTTP.Method.get);
    foreach(domain;response["data"].array)
        ret[domain["name"].str] = domain["id"].integer;
    return ret;
}

/// !!!! Following function deletes all of your domains. Use that with caution. Why anybody would need this, who knows.!!!!!!!
auto deleteAllDomains(DnsMadeEasy dns)
{
    return dns.restConnect("domains", HTTP.Method.del);
}

/*
    /domains/{domainName}
*/

///
auto getDomain(DnsMadeEasy dns, long domainID)
{
    return dns.restConnect("domains/" ~ domainID.to!string, HTTP.Method.get );
}

///
auto deleteDomain(DnsMadeEasy dns, string domainID)
{
    return dns.restConnect("domains/" ~ domainID, HTTP.Method.del);
}

///
auto addDomain(DnsMadeEasy dns, string domain)
{
    return dns.restConnect("domains/" ~ domain, HTTP.Method.put);
}

/**
    /domains/{domainName}/records
*/


///
auto getRecords(DnsMadeEasy dns, long domainID)
{
    return dns.restConnect("managed/" ~ domainID.to!string~"/records", HTTP.Method.get);
}

///
auto addRecord(DnsMadeEasy dns, long domainID, JSONValue data)
{
    return dns.restConnect("managed/" ~ domainID.to!string ~ "/records", HTTP.Method.post, data);
}

// /domains/{domainName}/records/{recordId}

///
auto getRecordById(DnsMadeEasy dns, long domainID, string id)
{
    return dns.restConnect("managed/" ~ domainID.to!string ~ "/records/" ~ id, HTTP.Method.get);
}

///
auto deleteRecordById(DnsMadeEasy dns, long domainID, string id)
{
    return dns.restConnect("managed/" ~ domainID.to!string ~ "/records/" ~ id, HTTP.Method.del);
}

/** NOT ACTUALLY POSSIBLE
///
auto updateRecordById(DnsMadeEasy dns,string domain, string id, JSONValue data)
{
    return dns.restConnect("domains/" ~ domain ~ "/records/" ~ id, HTTP.Method.put, data);
}
*/
