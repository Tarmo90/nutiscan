from nutiscan.checks.spa import is_spa_fallback


class R:
    def __init__(self, text, ctype):
        self.text = text
        self.ctype = ctype

    def header(self, key, default=""):
        return self.ctype if key == "content-type" else default


spa = R('<!doctype html><html><head></head><body><div id="root"></div></body></html>', "text/html")
real_json = R('{"name":"x","require":{}}', "application/json")
txt = R("Contact: mailto:info@nutifix.ee", "text/plain")

assert is_spa_fallback(spa) is True
assert is_spa_fallback(real_json) is False
assert is_spa_fallback(txt) is False
print("OK")
