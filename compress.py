import re
from collections import defaultdict, Counter

last_name = 0
CLOSING_CHAR = {
    "]":"[", "}":"{"
}

def objects(text, closing_char=CLOSING_CHAR):
    stack = []

    for i,c in enumerate(text):
        if c in closing_char.values():
            stack.append({"char": c, "pos": i})
            continue

        if c in closing_char and stack[-1]["char"] == closing_char[c]:
            start = stack.pop()
            yield text[start["pos"]: i+1]
            continue

def replace_and_append(text, obj):
    global last_name

    var_name = "obj" + str(last_name)
    last_name += 1
    return "var %s = %s;\n%s" % \
        (var_name, obj, text.replace(obj, var_name))

def compress(text):
    return reduce(replace_and_append,
                  sorted(set(objects(text)), reverse=True, key=len),
                  text)

# If this is still too large after the level one compression we should
# have no nested objects so for all Objects find the ones that have
# the same keys (ObjSet) and create prototypes with the most common
# values (P). Then instantiate each one removing the values that are
# the same.

def most_common_obj(txts):
    lines = zip(*[txt.split("\n") for txt in txts])
    mc_lines = [Counter(ll).most_common(1)[0][0] for ll in lines]
    mc_lines[0] += "\t// prototype"
    return "\n".join(mc_lines)

def object_diff(obj, proto):
    obj = obj.split("\n")
    proto = proto.split("\n")
    assert len(obj) == len(proto)

    cont = "\n".join([o for o,p in zip(obj[1:-1], proto[1:-1]) if o != p])
    return "{\n%s\n}" % cont

def proto_compress(text):
    last_name = 0
    obj_proto = defaultdict(lambda : [])
    # Sets of objects with common attributes
    for obj in objects(text, {'}':'{'}):
        ident = re.sub(":.*", "", obj)
        obj_proto[ident].append(obj)

    for obj_set in obj_proto.values():
        prototype = most_common_obj(obj_set)
        proto_name = "proto_" + str(last_name)
        last_name += 1
        text = "var " + proto_name + " = " + prototype + "\n" + text

        # Replace lean objects and set prototypes
        for obj in obj_set:
            name = "member_" + str(last_name)
            last_name += 1
            min_obj = object_diff(obj, prototype)
            text = "var %s = %s;\n%s%s.__proto__ = %s\n" % \
                   (name, min_obj,
                    text.replace(obj, name),
                    name, proto_name)

    return text

if __name__ == '__main__':
    import sys

    # Nothing is really gained of proto_compress. Avrdude.conf ins
    # still 14000 so we cant go much better than 16000 anyway.
    print compress(sys.stdin.read())
