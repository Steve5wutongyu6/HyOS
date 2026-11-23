import sys
p = sys.argv[1]
s = open(p).read()
if "name = hyverify;" in s:
    print("def already has hyverify")
    sys.exit(0)
block = """
module = {
  name = hyverify;
  common = hyverify.c;
  common = hysha.c;
  common = hygcm.c;
  common = aes.c;
  common = tweetnacl.c;
  cppflags = "-DAES256 -Ihyshim -Dmemcpy=grub_memcpy -Dmemset=grub_memset";
};

"""
anchor = s.index("name = echo;")
end = s.index("};", anchor) + 2
s = s[:end] + "\n" + block + s[end:]
open(p, "w").write(s)
print("def injected")
