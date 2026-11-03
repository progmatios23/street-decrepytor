from pathlib import Path
from jvm_lite import Interpreter, load_class

base = Path(r"D:\STREET-tool\out\unpacked\net\sydneyclient\loader")
classes = {}
for p in base.rglob("*.class"):
    jc = load_class(p)
    classes[jc.name] = jc
    print("loaded", jc.name, "methods", list(jc.methods)[:8])

vm = Interpreter(classes)
name = "net/sydneyclient/loader/sydney$d80eeccfcac2600d61a77f3e"
try:
    vm.clinit(name)
    print("statics", {k: (v if not isinstance(v, (bytes, list)) else (type(v), len(v), v[:40] if isinstance(v, (bytes, list)) else v)) for k, v in classes[name].statics.items()})
except Exception as e:
    print("clinit fail", type(e), e)

nat = "net/sydneyclient/loader/Natives"
try:
    vm.clinit(nat)
    print("Natives statics keys", list(classes[nat].statics.keys()))
    b = classes[nat].statics.get("b")
    c = classes[nat].statics.get("c")
    print("b", b)
    print("c", c)
    print("d", classes[nat].statics.get("d"))
except Exception as e:
    print("Natives clinit fail", type(e), e)

# try a(III) if clinit worked
try:
    if ("a", "(III)Ljava/lang/String;") in classes[nat].methods:
        s = vm.call(nat, "a", "(III)Ljava/lang/String;", [625728180, -7152, 0])
        print("a(III) sample", s)
except Exception as e:
    print("a(III) fail", type(e), e)
