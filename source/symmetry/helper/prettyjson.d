module symmetry.helper.prettyjson;
import std.json;
import std.conv;
import std.range:repeat;

string prettyPrint(JSONValue json, int indentLevel=0, string prefix="")
{
	import std.range:appender;
	auto ret=appender!string;
	ret.put('\t'.repeat(indentLevel));
	ret.put(prefix);
	//ret.put(' '.repeat(indentLevel*8));
	final switch(json.type)
	{
		alias string_ = immutable(char)[];
		case JSONType.null_:
			ret.put("<null>\n");
			return ret.data;
		case JSONType.string:
			ret.put(json.str~"\n");
			return ret.data;
		case JSONType.integer:
			ret.put(json.integer.to!string_~"\n");
			return ret.data;
		case JSONType.uinteger:
			ret.put(json.uinteger.to!string_~"\n");
			return ret.data;
		case JSONType.float_:
			ret.put(json.floating.to!string_~"\n");
			return ret.data;
		case JSONType.true_:
			ret.put("true\n");
			return ret.data;
		case JSONType.false_:
			ret.put("false\n");
			return ret.data;
		case JSONType.object:
			ret.put("{\n");
			foreach(key,value;json.object)
				ret.put(value.prettyPrint(indentLevel+1,key~" : "));
			ret.put('\t'.repeat(indentLevel));
			ret.put("}\n");
		return ret.data;
		case JSONType.array:
			ret.put("[\n");
			foreach(key;json.array)
				ret.put(prettyPrint(key,indentLevel+1));
			ret.put('\t'.repeat(indentLevel));
			ret.put("]\n");
			return ret.data;
	}
	assert(0);
}

