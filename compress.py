import time

closing_char = {
    "]":"[", "}":"{"
}

def new_name():
    return "v" + str(int(time.time()))

def objects(text):
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
    var_name = new_name()
    return "var %s = %s;\n%s" % \
        (var_name, obj, text.replace(obj, var_name))

def compress(text):
    return reduce(replace_and_append,
                  sorted(set(objects(text)), reverse=True, key=len),
                  text)

if __name__ == '__main__':
    print commpress("[{10}, [11], {10}]"))
