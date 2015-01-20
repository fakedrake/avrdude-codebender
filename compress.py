last_name = 0
closing_char = {
    "]":"[", "}":"{"
}

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
    global last_name

    var_name = "obj" + str(last_name)
    last_name += 1
    return "var %s = %s;\n%s" % \
        (var_name, obj, text.replace(obj, var_name))

def compress(text):
    return reduce(replace_and_append,
                  sorted(set(objects(text)), reverse=True, key=len),
                  text)

if __name__ == '__main__':
    import sys
    print compress(sys.stdin.read())
