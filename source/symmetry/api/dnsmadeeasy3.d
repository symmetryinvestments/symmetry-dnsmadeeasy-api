/**

	API for DNS Made Easy
	Ported to the D Programming Language (2015) by Laeeth Isharc and Kaleidic Associates

*/

///
module symmetry.api.dnsmadeeasy3;

import std.datetime: SysTime;
import std.net.curl: HTTP;
import std.json: JSONValue;

version(SIL)
{
	import kaleidic.sil.lang.typing.json : toVariable, toJsonString;
	void registerDnsMadeEasy(ref Handlers handlers)
	{
		handlers.openModule("net.dnsmadeeasy");
		scope(exit) handlers.closeModule();
		handlers.registerHandler!createDnsMadeEasy;
		handlers.registerHandler!randomPassword;
		handlers.registerHandler!joinUrl;
		handlers.registerHandler!listDomains;
		handlers.registerHandler!deleteAllDomains;
		handlers.registerHandler!getDomain;
		handlers.registerHandler!deleteDomain;
		handlers.registerHandler!addDomain;
		handlers.registerHandler!getRecords;
		handlers.registerHandler!addEasyRecord;
		handlers.registerHandler!addRecord;
		handlers.registerHandler!getRecordById;
		handlers.registerHandler!deleteRecordById;
		handlers.registerType!DnsMadeEasy;
		handlers.registerType!EasyResponse;
		handlers.registerType!EasyDomain;
		handlers.registerType!EasyDomainRecord;
		handlers.registerType!EasyDomainRecordHttpRed;
		handlers.registerType!EasyDomainRecordSecondary;
	}
}
else
{
	import asdf;
	struct SILdoc
	{
		string value;
	}
	auto toVariable(Asdf asdf)
	{
		return asdf;
	}
	string toJsonString(Asdf asdf)
	{
		return asdf.toJsonString;
	}	
	alias Variable = Asdf;
}
	



///
static immutable string[] weekDays=["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
///
static immutable string[] monthStrings= ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];


@SILdoc(`Generates a random password of length "n"`)
export string randomPassword(int n)
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

@SILdoc(`Form a complete URL joining "url" with "endpoint"`)
string joinUrl(string url, string endpoint)
{
	import std.exception: enforce;
	enforce(url.length > 0, "broken url");
	if (url[$-1] == '/')
		url = url[0..$-1];
	return url ~ "/" ~ endpoint;
}


/// Sat, 12 Feb 2011 20:59:04 GMT
string toHttpString(SysTime dt)
{
	import std.format: format;
	import std.conv: to;

	dt = dt.toUTC();
	return format!"%s, %02d %s %s %02d:%02d:%02d %s"
	(   weekDays[dt.dayOfWeek.to!size_t],
		dt.day,
		monthStrings[dt.month-1],
		dt.year,
		dt.hour,
		dt.minute,
		dt.second,
		"UTC"       // since we converted dt to UTC
	);
}

///
struct HashResult
{
	string date;
	string value;
}

@SILdoc(`Initializes a new DnsMadeEasy structure. Initial values are imported from shell `~
`environment variables, so you should make sure to export them before running your sil script, eg:

    export DNSMADEEASY_TOKEN="79..."
    export DNSMADEEASY_SECRET="FILLMEIN"

then run a sil script:
    import * from dnsmadeeasy
    client = createDnsMadeEasy()
    print(json.toJsonString(client |> listDomains()))
`)
DnsMadeEasy createDnsMadeEasy()
{
	import std.process:environment;
	auto token = environment.get("DNSMADEEASY_TOKEN", "");
	auto secret = environment.get("DNSMADEEASY_SECRET", "");
	return DnsMadeEasy(token, secret);
}

@SILdoc(`Contains information and methods to access the DNS Made Easy API`)
struct DnsMadeEasy
{
	string api;
	string secret;
	enum endPoint="http://api.dnsmadeeasy.com/V2.0/dns/";

	// dns.:Sat, 12 Feb 2011 20:59:04 GMT
	//return strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime());


	private auto createHash()
	{
		import std.datetime: Clock;
		import std.string: representation;
		import std.digest.hmac: hmac;
		import std.digest.sha: SHA1;
		import std.digest: toHexString, LetterCase;

		auto date = Clock.currTime
				.toHttpString;
		return HashResult(date,
				date.representation
				.hmac!SHA1(this.secret.representation)
				.toHexString!(LetterCase.lower).dup);
	}
}

@SILdoc(`Represents information about the rate limits imposed by the API`)
struct EasyResponse
{
	@SILdoc(`A unique identifier of the API call that was sent.`)
	long id;
	@SILdoc(`Maximum number of requests allowed by the API`)
	long requestLimit;
	@SILdoc(`Remaining number requests until the limit is exceeded`)
	long requestsRemaining;
}

@SILdoc(`Stores information about a domain`)
struct EasyDomain
{
	@SILdoc(`The domain name`)
	string name;				// name
	@SILdoc(`list of nameservers assigned to the domain`)
	string[] nameServers;		// nameServer
	@SILdoc(`Whether this domain uses the Global Traffic Director service`)
	bool gtdEnabled;			// gtdEnabled
}

@SILdoc(`Type of DNS record`)
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

@SILdoc(`Global traffic director region`)
enum EasyDirectorLocation
{
	Default,
	US_East,
	US_West,
	Europe
}

@SILdoc(`DNS record for a given domain`)
struct EasyDomainRecord
{
	@SILdoc(`Unique record identifier`)
	int id;
	@SILdoc(`Name of the record, eg ns1`)
	string name;
	@SILdoc(`Type of DNS record`)
	EasyDomainRecordType type;
	// ??
	string data;
	@SILdoc(`TTL of this record`)
	int ttl;
	@SILdoc(`Global traffic director location`)
	EasyDirectorLocation gtdLocation;
	@SILdoc(`Per-record password for a Dynamic DNS update`)
	string dynamicPassword;				/// for dynamic DNS
	@SILdoc(`HTTPRED record type`)
	EasyDomainRecordHttpRed httpRed;
}

@SILdoc(`HTTPRED record type`)
struct EasyDomainRecordHttpRed
{
	@SILdoc(`A description of the HTTPRED record`)
	string description;
	@SILdoc(`Keywords associated with the HTTPRED record`)
	string keywords;
	@SILdoc(`The title fo the HTTPRED record`)
	string title;
	@SILdoc(`Type of redirection. Possible values: Hidden Frame Masked; Standard – 302; and `~
	`Standard – 301. The first represents the target URL in a frame without changing the URL, `~
	`the 301 is a normal redirect and the 302 is a temporal redirect`)
	string redirectType;
	@SILdoc(`When redirecting, the hard link mode removes any subdirectory or file from the path
	of the request`)
	bool hardLink;
}

@SILdoc(`Represents a secondary DNS - a slave DNS that gets DNS updates via AXFR. "name" is the `~
`server name and "ipMaster" is a list of the master's IPs`)
struct EasyDomainRecordSecondary
{
	string name;
	string[] ipMaster;
}

private auto restConnect(DnsMadeEasy dns, string resource, HTTP.Method method)
{
	JSONValue params;
	return restConnect(dns, resource, method, params);
}

private auto restConnect(DnsMadeEasy dns, string resource, HTTP.Method method, JSONValue params)
{
	import std.exception: enforce;
	import std.array: appender;
	import std.json: parseJSON;

	enforce(dns.api.length > 0 && dns.secret.length > 0, "must provide API and token first");
	auto url = dns.endPoint.joinUrl(resource);
	auto client = HTTP(url);
	auto hash = dns.createHash;
	client.addRequestHeader("x-dnsme-apiKey", dns.api);
	client.addRequestHeader("x-dnsme-requestDate", hash.date);
	client.addRequestHeader("x-dnsme-hmac", hash.value);

	auto response = appender!(ubyte[]);
	client.method = method;
	client.setPostData(cast(void[])params.toString, "application/json");

	client.onReceive = (ubyte[] data)
	{
		response.put(data);
		return data.length;
	};
	client.perform();  // rely on curl to throw exceptions on 204, >=500
	return cast(string) response.data;
}

@SILdoc(`Get all the domains and their domain ID. "dns" is a DnsMadeEasy struct that you must have `~
`got from createDnsMadeEasy()`)
export long[string] listDomains(DnsMadeEasy dns)
{
	import std.array: appender;
	import std.json: parseJSON;

	long[string] ret;
	auto response = parseJSON(dns.restConnect("managed", HTTP.Method.get));
	foreach(domain; response["data"].array)
		ret[domain["name"].str] = domain["id"].integer;
	return ret;
}

@SILdoc(`/!\ WARNING /!\: This function deletes ALL of your domains. Use that with CAUTION. "dns" `~
`is a DnsMadeEasy struct that you must have got from createDnsMadeEasy()`)
export auto deleteAllDomains(DnsMadeEasy dns)
{
	import asdf;
	return dns.restConnect("managed", HTTP.Method.del).parseJson.toVariable;
}


@SILdoc(`Get information for the domain with a given "domainID". "dns" is a DnsMadeEasy struct `~
`that you must have got from createDnsMadeEasy()`)
export auto getDomain(DnsMadeEasy dns, long domainID)
{
	import std.conv: to;
	import asdf;
	return dns.restConnect("managed/" ~ domainID.to!string, HTTP.Method.get ).parseJson.toVariable;
}

@SILdoc(`Delete the domain corresponding to the given "domainID". "dns" is a DnsMadeEasy struct `~
`that you must have got from createDnsMadeEasy()`)
export auto deleteDomain(DnsMadeEasy dns, string domainID)
{
	import asdf;
	return dns.restConnect("managed/" ~ domainID, HTTP.Method.del).parseJson.toVariable;
}

@SILdoc(`Add a domain, the domain name is specified in "domain". "dns" is a DnsMadeEasy struct `~
`that you must have got from createDnsMadeEasy()`)
export auto addDomain(DnsMadeEasy dns, string domain=null)
{
	import asdf;

	JSONValue data;
	if(domain.length > 0)
		data["name"] = domain;
	return dns.restConnect("managed/", HTTP.Method.post, data).parseJson.toVariable;
}


/* managed/{domainName}/records */
@SILdoc(`Get the DNS records for a given domain id specified in "domainID". "dns" is a DnsMadeEasy `~
`struct that you must have got from createDnsMadeEasy()`)
export auto getRecords(DnsMadeEasy dns, long domainID)
{
	import std.conv: to;
	import asdf;
	return dns.restConnect("managed/" ~ domainID.to!string~"/records", HTTP.Method.get).parseJson.toVariable;
}


//Note: There is no such thing as "dynamicPassword" for DDNS in the API, only a "dynamicDns"
// boolean and a password field
@SILdoc(`Add a new record to a domain. "domainID" is the domain ID, "name" is the name field, `~
`"value" is the IP address, "type" is the type of record, "ttl" is the Time To Live, that is, the `~
`expiration time measured in seconds, and a "dynamicPassword" string to specify the password used `~
`for dynamic DNS updates. "dns" is a DnsMadeEasy struct that you must have got from createDnsMadeEasy()`)
export auto addEasyRecord(DnsMadeEasy dns, long domainID, string name, string value,
		string type = "A", string gtdLocation = "DEFAULT", int ttl=86_400, string dynamicPassword=null)
{
	import std.conv: to;
	import asdf;

	JSONValue data;
	data["name"] = name;
	data["type"] = type;
	data["value"] = value;
	data["ttl"] = ttl;
	data["gtdLocation"] = gtdLocation;
	if(dynamicPassword.length > 0)
		data["dynamicPassword"] = dynamicPassword;
	return dns.restConnect("managed/" ~ domainID.to!string ~ "/records", HTTP.Method.post, data).parseJson.toVariable;
}

@SILdoc(`Add a new record to a domain. Like addEasyRecord, but all the missing parameters are passed `~
`inside of "data". "domainID" is the domain ID. "dns" is a DnsMadeEasy struct that you must have got `~
`from createDnsMadeEasy()`)
export auto addRecord(DnsMadeEasy dns, long domainID, Variable data)
{
	import std.conv: to;
	import std.json: parseJSON;
	import asdf;
	auto jsonData = data.toJsonString().parseJSON; // we should move to asdf and get rid of std.json
	return dns.restConnect("managed/" ~ domainID.to!string ~ "/records", HTTP.Method.post, jsonData).parseJson.toVariable;
}

// /managed/{domainName}/records/{recordId}

@SILdoc(`Get a specific type of record. "domainID" is the domain ID, "id" is the record id `~
`"dns" is a DnsMadeEasy struct that you must have got from createDnsMadeEasy()`)
export auto getRecordById(DnsMadeEasy dns, long domainID, string id)
{
	import std.conv: to;
	import asdf;
	return dns.restConnect("managed/" ~ domainID.to!string ~ "/records/" ~ id, HTTP.Method.get).parseJson.toVariable;
}

@SILdoc(`Delete a record referenced by record ID, passed in "id". "domainID" is the domain ID. "dns" `~
`is a DnsMadeEasy struct that you must have got from createDnsMadeEasy()`)
export auto deleteRecordById(DnsMadeEasy dns, long domainID, string id)
{
	import std.conv: to;
	import asdf;
	return dns.restConnect("managed/" ~ domainID.to!string ~ "/records/" ~ id, HTTP.Method.del).parseJson.toVariable;
}

/** NOT ACTUALLY POSSIBLE
///
auto updateRecordById(DnsMadeEasy dns,string domain, string id, JSONValue data)
{
	return dns.restConnect("domains/" ~ domain ~ "/records/" ~ id, HTTP.Method.put, data);
}
*/

