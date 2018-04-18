version(KaleidicDnsTest)
{
    ///
    void main(string[] args)
    {
        import kaleidic.api.dnsmadeeasy: DnsMadeEasy, listDomains, getRecords, getDomain, deleteDomain;
        import std.process: environment;
        import std.array: front;
        import std.stdio: writeln, writefln;

        auto dnsMadeEasyToken=environment.get("DNSMADEEASY_TOKEN");
        auto dnsMadeEasySecret=environment.get("DNSMADEEASY_SECRET");
        auto dns = DnsMadeEasy(dnsMadeEasyToken, dnsMadeEasySecret);
        //writefln("hash: %s",dns.createHash);
        // listDomains: returns a list of all domains
        writefln("\nList all domains: \n");
        auto domains = dns.listDomains;
        foreach(i, d; domains)
            writeln(d);

        // listRecords for a single domain
        writefln("\nList records for a single domain:");
        auto records = dns.getRecords(domains.keys);
        foreach(entry;records.array)
        {
            writefln("");
            foreach(key, value;entry.object)
                writefln("%s : %s",key,value.to!string);
        }

        // getDomain for a single domain
        writefln("\nGet general info about a single domain: \n");
        auto domainInfo = dns.getDomain(domains.front);
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
} else {
    void main(string[] args)
    {
        import kaleidic.api.dnsmadeeasy: DnsMadeEasy, listDomains, getRecords, randomPassword, addRecord, deleteRecordById;
        import std.stdio: writefln;
        import std.string: strip, toLower;
        import std.conv: to;
        import std.json: JSONValue;

        enum baseDomain="symmetry.host";
        import std.process;
        auto dnsMadeEasyToken=environment.get("DNSMADEEASY_TOKEN");
        auto dnsMadeEasySecret=environment.get("DNSMADEEASY_SECRET");
        auto dns = DnsMadeEasy(dnsMadeEasyToken, dnsMadeEasySecret);

        auto domains = dns.listDomains;
        // listRecords for a single domain
        //writefln("\nList records for a single domain:");
        auto records = dns.getRecords(domains["symmetry.host"]);
        long id=-1;
        foreach(entry;records["data"].array)
        {
            auto q = "name" in entry;
            if (q! is null)
            {
                if(entry["name"].str.strip.toLower==args[1].strip.toLower)
                {
                    auto p = "id" in entry;
                    if (p !is null)
                        id = (*p).integer;
                    debug
                    {
                        foreach(key, value;entry.object)
                            writefln("%s : %s",key,value.to!string);
                    }
                }
            }
        }

        // getDomain for a single domain
        //writefln("\nGet general info about a single domain: \n");
        //auto domainInfo = dns.getDomain(domains["symmetry.host"]);
        //writefln("%s",domainInfo.prettyPrint);
        JSONValue result;

        if(id>0)
        {
            //writefln("\nDeleting old record:\n");
            result = dns.deleteRecordById(domains[baseDomain],id.to!string);
            //writefln("%s",result);
        }
        auto password = randomPassword(12);
        JSONValue data;
        //writefln("\nAdd record to domain: \n");
        data["name"]=args[1];
        data["type"]="A";
        data["dynamicDns"] = true;
        data["value"] = args[2];
        data["password"] = password;
        //data["gtdLocation"]="DEFAULT";
        data["ttl"]=200;
        result = dns.addRecord(domains[baseDomain], data);
        //writefln(result.prettyPrint);
        writefln("%s",args[1]);
        writefln("%s",result["id"]);
        writefln("%s",password);
        /*JSONValue record;
          record = dns.getRecordById("kaleidicassociates.com","6883496");
          writefln(record.prettyPrint);

          record = dns.deleteRecordById("test1.com", "6883496");

          data=JSONValue(null);
          data["name"]="";
        */
    }
}
