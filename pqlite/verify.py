# from g1mn/pq-proof 7b7803f (MIT)
# 수정: JAVA 종류(.java .kt .kts .groovy .scala)와 Java·Spring·JDK 규칙(deny), review() 검토 등급 규칙,
#       Spring 설정 읽기(_props: .properties·YAML 펼침·-D·setProperty·환경 변수 이름), 위 요약 주석.
"""TLS 약화 수정 검사(PQ-Proof verify.py에 Java·Spring을 보탬).

바뀐 파일마다 수정 전후를 그 파일의 파서처럼 읽어(주석 제거, 문자열 처리) 규칙별 개수를 비교한다.
- weakening(changed): deny 등급. 늘면 안 되는 것(added), 줄면 안 되는 것(removed), 값이 바뀌면 안 되는 것
  (changed), 낮아지면 안 되는 것(lowered). 하나라도 있으면 prove.sh가 실패로 친다.
- review(changed): review 등급. 앱 계층 검증이 줄어든 흔적(서명 검증·복호 호출 수가 패치 전체에서 줄었다,
  verify·isValid·check 이름 메서드 몸통이 성공만 돌려준다). 리팩터링으로도 생기므로 실패가 아니고 사람이
  줄마다 사유를 단다(전환하면서 암호 검증을 건너뛰고 성공만 돌려주는 코드를 놓치지 않으려는 규칙).
아래는 PQ-Proof 원문 설명이다.

Deterministic check for TLS-weakening changes in a patch.

The allowlist (plan.py) says which files may change, never what goes into them, and the model's
input includes text from the target repo (its files, its build errors), so a prompt injection can
ask for certificate verification to be turned off. This check reads each changed file before and
after the patch and refuses the patch when a rule goes the wrong way:
- "added": a weakening construct appears more often after the patch (InsecureSkipVerify, a
  verification callback, rejectUnauthorized: false, verify=False, CERT_NONE, proxy_ssl_verify off,
  TLS 1.0/1.1 by name or as a number, a weak cipher suite, a GODEBUG setting that brings back
  legacy TLS ...);
- "removed": a verification setting appears less often. nginx's proxy_ssl_verify is off by
  default, so deleting `proxy_ssl_verify on;` turns upstream verification off as surely as
  writing `off`; the same goes for a trusted-CA file, client-certificate verification, Go's
  RootCAs or ClientCAs left out of a replaced tls.Config, and a MinVersion line;
- "changed": a trust setting gets a value the file did not have (another CA file, another
  RootCAs expression): trusting different CAs is not part of a key-exchange migration;
- "lowered": the lowest value of a setting goes down (Go MinVersion, the go.mod go line, whose
  older defaults include TLS 1.0 servers and RSA key exchange).
Counts, not lines, so moving a setting within a file is fine and commenting it out is not.

Each file is read the way its own parser reads it, because a comment marker inside a string or a
word is not a comment (the day-3 review hid `ssl_protocols TLSv1` behind `edge#2;`, which nginx
reads as a word, and Go settings behind "a//b" and "docs/*"):
- nginx: tokenized as nginx does it (ngx_conf_read_token): `#` starts a comment only where a word
  could start, quotes and backslash escapes are resolved, and each statement becomes one line
  `name arg ...;`. Rules match whole statements, so `proxy_ssl_verify on;` kept inside a quoted
  header value, or as words of another directive, is not the setting. Values compare without case,
  as nginx compares them.
- Go and go.mod: comments are removed outside string and rune literals (raw strings included);
  `//go:` directives stay, because //go:debug sets GODEBUG. "removed" rules also ignore what is
  inside string literals.
- JavaScript and Python: the same with their quote rules, but these scanners are approximate (a
  JavaScript regular expression literal, nested f-string quotes), so "added" rules also count the
  raw text: a comment that names a weakening construct is refused too.
- Anything else (Dockerfile, Makefile, shell, YAML): only lines that start with `#` are comments.
It is a deny list for the changes a key-exchange migration never needs; anything it does not name
passes, and the probe still decides whether the key exchange works. What it cannot see is listed
in the README's "Known limits": nginx's block structure (a setting moved into a location no
request reaches keeps its count), values built at run time (reflect, names composed from parts,
settings in files the patch does not touch).
"""
import re

GO, GOMOD, NGINX, PY, JS, ANY = "go", "go.mod", "nginx", "python", "js", "any"
JAVA = "java"  # 오프라인판 추가: Java·Kotlin·Groovy·Scala

# ---------------------------------------------------------------------------------------------
# Reading each kind of file the way its parser does.
GO_TOKENS = re.compile(r"//[^\n]*|/\*.*?(?:\*/|\Z)|\"(?:\\.|[^\"\\\n])*(?:\"|$)|'(?:\\.|[^'\\\n])*(?:'|$)|`[^`]*(?:`|\Z)",
                       re.S | re.M)
GOMOD_TOKENS = re.compile(r"//[^\n]*|\"(?:\\.|[^\"\\\n])*(?:\"|$)|`[^`]*(?:`|\Z)", re.S | re.M)  # go.mod has no /* */
JS_TOKENS = re.compile(r"//[^\n]*|/\*.*?(?:\*/|\Z)|\"(?:\\.|[^\"\\\n])*(?:\"|$)|'(?:\\.|[^'\\\n])*(?:'|$)|`(?:\\.|[^`\\])*(?:`|\Z)",
                       re.S | re.M)
PY_TOKENS = re.compile(r"#[^\n]*|\"\"\"(?:\\.|[^\\])*?(?:\"\"\"|\Z)|'''(?:\\.|[^\\])*?(?:'''|\Z)|"
                       r"\"(?:\\.|[^\"\\\n])*(?:\"|$)|'(?:\\.|[^'\\\n])*(?:'|$)", re.S | re.M)
# Java: 텍스트 블록("""...""")을 일반 문자열보다 먼저 읽는다. 문자 리터럴('a')도 문자열처럼 비운다.
JAVA_TOKENS = re.compile(r"//[^\n]*|/\*.*?(?:\*/|\Z)|\"\"\"(?:\\.|[^\\])*?(?:\"\"\"|\Z)|\"(?:\\.|[^\"\\\n])*(?:\"|$)|"
                         r"'(?:\\.|[^'\\\n])*(?:'|$)", re.S | re.M)
LINE_COMMENT = re.compile(r"^[ \t]*#[^\n]*", re.M)
NGINX_ODD = re.compile(r"[\s;{}\x00]")  # inside a word these would read as a statement boundary


def _spaces(t):
    return re.sub(r"[^\n]", " ", t)


def _views(text, tokens, keep_positions=False):
    """(code, bare): comments removed; bare also empties string and rune literals. With
    keep_positions, what is removed becomes spaces (newlines kept), so offsets and line numbers
    stay: the CBOM scanner (scan.py) reads files this way to report lines."""
    def drop(t):
        return _spaces(t) if keep_positions else ""

    def code(m):
        t = m[0]
        if t.startswith("//"):
            return t if t.startswith("//go:") else drop(t)
        if t.startswith("/*"):
            return _spaces(t) if keep_positions else ("\n" if "\n" in t else " ")
        if t.startswith("#"):
            return drop(t)
        return t

    def bare(m):
        t = m[0]
        if t[:1] in "\"'`":
            q = t[:3] if t[:3] in ('"""', "'''") else t[:1]
            return q + _spaces(t[len(q):]) if keep_positions else q + q
        return code(m)
    return tokens.sub(code, text), tokens.sub(bare, text)


def nginx_statements(text, with_lines=False):
    """nginx's own reading of a config (ngx_conf_read_token): a list of statements, each a list
    of words ending with ";", "{" or "}". A '#' starts a comment only where a word could start;
    quotes and the escapes nginx knows are resolved. with_lines: (line of the statement's first
    word, words) instead."""
    out, words, word, quote, var, start = [], [], None, None, False, 0
    i, n = 0, len(text)
    seen, line = 0, 1  # line numbers are counted forward: statements come in order

    def emit(st, at):
        nonlocal seen, line
        if with_lines:
            line += text.count("\n", seen, at)
            seen = at
            out.append((line, st))
        else:
            out.append(st)
    while i < n:
        c = text[i]
        if word is None:
            if c in " \t\r\n":
                i += 1
                continue
            if c == "#":
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if c in ";{":
                emit(words + [c], start if words else i)
                words, i = [], i + 1
                continue
            if c == "}":
                if words:
                    emit(words, start)
                emit(["}"], i)
                words, i = [], i + 1
                continue
            if not words:
                start = i
            word, var = [], False
            if c in "\"'":
                quote, i = c, i + 1
                continue
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            word.append({"t": "\t", "r": "\r", "n": "\n"}.get(nxt, nxt) if nxt in "\"'\\trn" else c + nxt)
            i += 2
            continue
        if quote:
            if c == quote:
                words.append("".join(word))
                word = quote = None
            else:
                word.append(c)
            i += 1
            continue
        if c == "{" and var:
            word.append(c)
            i += 1
            continue
        if c in " \t\r\n;{":
            words.append("".join(word))
            word = None
            continue
        var = c == "$"
        word.append(c)
        i += 1
    if word is not None:
        words.append("".join(word))
    if words:
        emit(words, start)
    return out


def _nginx_view(text):
    lines = []
    for st in nginx_statements(text):
        if st == ["}"]:
            lines.append("}")
            continue
        end = st[-1] if st[-1] in (";", "{") else ""
        words = [NGINX_ODD.sub("\x00", w) or "\x00" for w in (st[:-1] if end else st)]
        lines.append(" ".join(words) + (" {" if end == "{" else end))
    return "\n".join(lines) + "\n"


def views(text, kind, keep_positions=False):
    """(code, bare) of text as kind's parser reads it: what rules count. keep_positions: removed
    text becomes spaces, newlines kept (not for nginx, whose view is one line per statement: use
    nginx_statements(text, with_lines=True))."""
    if kind == NGINX:
        if keep_positions:
            raise ValueError("nginx: use nginx_statements(text, with_lines=True)")
        v = _nginx_view(text)
        return v, v
    if kind in (GO, GOMOD, JS, PY, JAVA):
        return _views(text, {GO: GO_TOKENS, GOMOD: GOMOD_TOKENS, JS: JS_TOKENS, PY: PY_TOKENS, JAVA: JAVA_TOKENS}[kind],
                      keep_positions)
    v = LINE_COMMENT.sub(lambda m: _spaces(m[0]) if keep_positions else "", text)
    return v, v


def strip_comments(text, kind):
    """Text without comments, read the way kind's parser reads it (see views)."""
    return views(text, kind)[0]


# ---------------------------------------------------------------------------------------------
# Values the rules read.
GO_VERSIONS = {"VersionSSL30": 0x0300, "VersionTLS10": 0x0301, "VersionTLS11": 0x0302, "VersionTLS12": 0x0303,
               "VersionTLS13": 0x0304}
TLS12 = 0x0303
# GODEBUG settings that bring back what newer Go turned off: TLS 1.0/1.1 servers, RSA key exchange,
# 3DES, the unsafe EKM, SHA-1 signatures in TLS 1.2 and in certificates.
LEGACY_GODEBUG = r"\b(?:tls10server|tlsrsakex|tls3des|tlsunsafeekm|tlssha1|x509sha1)\s*=\s*1\b"
GODEBUG_DEFAULT = re.compile(r"\bdefault\s*=\s*go1\.(\d+)")
GODEBUG_DEFAULT_MIN = 23  # Go 1.22 turned off tls10server and tlsrsakex by default, Go 1.23 tls3des
# One part of an OpenSSL cipher string (parts of a token are joined with +; a token after ! or -
# removes suites and never counts) that selects a weak suite: everything, low or export strength,
# no encryption or no authentication, single DES, 3DES, RC4, RC2, MD5, RSA key exchange (kRSA,
# RSA, the OpenSSL names without a key-exchange prefix, the IANA TLS_RSA_WITH_ names, RSA-PSK).
WEAK_OPENSSL_PART = re.compile(
    r"(?i)(?:ALL|COMPLEMENTOFALL|COMPLEMENTOFDEFAULT|LOW|EXP(?:ORT)?(?:40|56)?|DES|kRSA|RSA|RSA-PSK-.*|TLS_RSA_\w*|"
    r".*(?:3DES|DES-CBC|DES_CBC|DES40|RC4|RC2|NULL|EXP-|EXPORT|MD5).*|"
    r"(?:AES|CAMELLIA|ARIA|SEED|IDEA)[A-Z0-9-]*-(?:SHA[0-9]*|CCM8?))")
SECLEVEL0 = re.compile(r"(?i)\bSECLEVEL\s*=\s*0\b")
UPSTREAM = ("proxy_", "grpc_", "uwsgi_")
OLD_PROTOCOLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.1"}
GO_SET = r"\s*(?::=|[:=](?!=))\s*"  # an assignment or a struct field, not ==
GO_VERSION_VALUE = re.compile(rf"\b(?:Min|Max)Version{GO_SET}([^,;\n}}]+)")
GO_SUITE_LIST = re.compile(r"\[\]uint16\s*\{([^}]*)\}")
GO_SUITES_SET = re.compile(rf"\bCipherSuites{GO_SET}(?!\[\]uint16\s*\{{)\S")
GO_NAMED_SUITE = re.compile(r"(?:\w+\.)?TLS_\w+")
GO_MOD_GO = re.compile(r"^go\s+1\.(\d+)(?:\.\d+)?\s*$", re.M)


def _nginx_lines(text):
    """(name, args) of each statement of an nginx view."""
    for line in text.splitlines():
        if line.endswith(";"):
            words = line[:-1].split(" ")
            yield words[0], words[1:]


def _directive(name, base):
    return name == base or (name.endswith(base) and name[:-len(base)] in UPSTREAM)


def _weak_ciphers(text):
    n = 0
    for name, args in _nginx_lines(text):
        if _directive(name, "ssl_ciphers"):
            value = " ".join(args)
        elif _directive(name, "ssl_conf_command") and args and args[0].lower() == "cipherstring":
            value = " ".join(args[1:])
        else:
            continue
        for token in re.split(r"[:,\s]+", value):
            if not token or token[0] in "!-":
                continue
            if SECLEVEL0.search(token) or any(WEAK_OPENSSL_PART.fullmatch(p) for p in token.lstrip("+").split("+") if p):
                n += 1
    return n


def _nginx_old_protocols(text):
    n = 0
    for name, args in _nginx_lines(text):
        if _directive(name, "ssl_protocols"):
            n += sum(1 for a in args if a.lower() in OLD_PROTOCOLS)
    return n


def _nginx_min_protocol(text):
    """ssl_conf_command (or proxy_...) MinProtocol below TLS 1.2 or None, or Protocol enabling one."""
    n = 0
    for name, args in _nginx_lines(text):
        if not _directive(name, "ssl_conf_command") or len(args) < 2:
            continue
        cmd, value = args[0].lower(), " ".join(args[1:]).lower()
        if cmd == "minprotocol" and value in OLD_PROTOCOLS | {"none"}:
            n += 1
        elif cmd == "protocol":
            n += sum(1 for p in re.split(r"[,\s]+", value) if p in OLD_PROTOCOLS | {"all"})
    return n


def _nginx_trust(text):
    return {f"{name} {' '.join(args)}" for name, args in _nginx_lines(text)
            if _directive(name, "ssl_trusted_certificate") or name in ("ssl_client_certificate", "ssl_crl")
            or _directive(name, "ssl_crl")}


def _go_int(s):
    """A Go integer literal's value (0x, 0o, 0b, a leading 0 for octal, _ separators), or None."""
    s = s.replace("_", "")
    for pattern, base in ((r"0[xX][0-9a-fA-F]+", 16), (r"0[oO][0-7]+", 8), (r"0[bB][01]+", 2), (r"0[0-7]*", 8),
                          (r"[1-9][0-9]*", 10)):
        if re.fullmatch(pattern, s):
            return int(s[2:] if s[1:2] in "xXoObB" and len(s) > 2 else s, base)
    return None


def _go_version_values(text):
    """The value of every MinVersion or MaxVersion setting: a number, or None when the check cannot
    read it (an expression, a variable, a rune)."""
    out = []
    for m in GO_VERSION_VALUE.finditer(text):
        v = m[1].strip()
        inner = re.fullmatch(r"uint16\s*\(\s*(.*?)\s*\)", v)
        v = inner[1] if inner else v
        named = re.fullmatch(r"(?:\w+\.)?(Version\w+)", v)
        out.append(GO_VERSIONS.get(named[1]) if named else _go_int(v))
    return out


def _go_old_numbers(text):
    return sum(1 for v in _go_version_values(text) if v is not None and v < TLS12)


def _go_unread_versions(text):
    return sum(1 for v in _go_version_values(text) if v is None)


def _go_min_versions(text):
    return [v for v in _go_version_values(text) if v is not None]


def _go_unread_suites(text):
    """Cipher suites the check cannot name: numbers or expressions in a []uint16 list, or a
    CipherSuites value that is not a list written out."""
    n = len(GO_SUITES_SET.findall(text))
    for m in GO_SUITE_LIST.finditer(text):
        n += sum(1 for e in m[1].split(",") if e.strip() and not GO_NAMED_SUITE.fullmatch(e.strip()))
    return n


def _old_godebug_default(text):
    return sum(1 for m in GODEBUG_DEFAULT.finditer(text) if int(m[1]) < GODEBUG_DEFAULT_MIN)


def _go_trust(text):
    return {f"{m[1]}: {m[2].strip()}" for m in re.finditer(rf"\b(RootCAs|ClientCAs){GO_SET}([^,;\n}}]+)", text)}


def _go_lines(text):
    return [int(m[1]) for m in GO_MOD_GO.finditer(text)]


def _nginx(pattern):
    """A whole nginx statement: name, then words separated by one space (see nginx_statements)."""
    return re.compile("^" + pattern + "$", re.M)


# ---------------------------------------------------------------------------------------------
# 오프라인판 추가: Java·Spring·JDK 설정을 읽는 함수들.
OLD_JAVA_PROTOCOLS = {"sslv2", "sslv2hello", "sslv3", "tlsv1", "tlsv1.1"}
J_CALL_ARGS = re.compile(r"\bset(?:Enabled)?Protocols\s*\(([^;]*)")
J_STRING = re.compile(r"\"((?:\\.|[^\"\\\n])*)\"")


def _old_tokens(value):
    """값 문자열 안의 옛 프로토콜 이름 수(TLSv1·TLSv1.1·SSLv3, TLSv1.2와 TLSv1.3은 아님)."""
    return sum(1 for t in re.split(r"[\s,;:\[\]\"'()+]+", value) if t.lower() in OLD_JAVA_PROTOCOLS)


def _java_old_protocols(text):
    """setEnabledProtocols(...)·setProtocols(...) 인자에 든 옛 프로토콜 문자열 수."""
    return sum(_old_tokens(" ".join(J_STRING.findall(m[1]))) for m in J_CALL_ARGS.finditer(text))


def _java_empty_trust(text):
    """몸통이 빈 checkServerTrusted·checkClientTrusted(모든 인증서를 믿는 TrustManager)."""
    return len(re.findall(r"\bcheck(?:Server|Client)Trusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+?)?\{\s*\}", text))


def _canon_key(key):
    """Spring 느슨한 이름 맞추기: 소문자, '_'는 '.', '-'는 뺀다(SERVER_SSL_ENABLEDPROTOCOLS = server.ssl.enabled-protocols)."""
    return key.strip().lower().replace("_", ".").replace("-", "")


PROP_LINE = re.compile(r"^[ \t]*(?:-[ \t]+)?([A-Za-z0-9_.\[\]-]+)[ \t]*[=:][ \t]*(.*?)[ \t]*$")
YAML_KEY = re.compile(r"^([ \t]*)(?:-[ \t]+)?([A-Za-z0-9_.\[\]-]+)[ \t]*:(?:[ \t]+(.*?))?[ \t]*$")
YAML_ITEM = re.compile(r"^[ \t]*-[ \t]+([^:#\n]+?)[ \t]*$")
D_FLAG = re.compile(r"-D([A-Za-z0-9_.\[\]-]+)=([^\s\"']*)")
SET_PROPERTY = re.compile(r"\b(?:System|Security)\s*\.\s*setProperty\s*\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]*)\"")


def _props(text):
    """{(줄, 정규화한 키, 값)}: .properties 줄, YAML을 펼친 키, -Dk=v, System/Security.setProperty("k", "v").
    같은 줄을 두 방식이 같이 읽어도 집합이라 한 번만 센다. YAML 흐름 목록([a, b])과 블록 목록(- a)도 값으로 읽는다."""
    out, stack = set(), []
    for no, line in enumerate(text.split("\n"), 1):
        m = PROP_LINE.match(line)
        if m and not line.lstrip().startswith(("#", "!")):
            out.add((no, _canon_key(m[1]), m[2].strip().strip("'\"")))
        y = YAML_KEY.match(line)
        if y:
            indent = len(y[1].expandtabs())
            while stack and stack[-1][0] >= indent:
                stack.pop()
            full = ".".join([k for _, k in stack] + [y[2]])
            if y[3] is None or y[3] == "":
                stack.append((indent, y[2]))
            else:
                out.add((no, _canon_key(full), y[3].split(" #")[0].strip().strip("'\"")))
        else:
            item = YAML_ITEM.match(line)
            if item and stack:
                out.add((no, _canon_key(".".join(k for _, k in stack)), item[1].strip().strip("'\"")))
        for d in D_FLAG.finditer(line):
            out.add((no, _canon_key(d[1]), d[2]))
        for s in SET_PROPERTY.finditer(line):
            out.add((no, _canon_key(s[1]), s[2]))
    return out


def _prop_count(keys, test):
    """keys(정규화한 키 정규식)에 맞고 test(값)가 참인 설정 줄 수."""
    rx = re.compile(keys)
    return lambda text: sum(1 for _, k, v in _props(text) if rx.fullmatch(k) and test(v))


def _prop_values(keys):
    rx = re.compile(keys)
    return lambda text: {f"{k}={v}" for _, k, v in _props(text) if rx.fullmatch(k)}


def _prop_old_protocols(keys):
    rx = re.compile(keys)
    return lambda text: sum(_old_tokens(v) for _, k, v in _props(text) if rx.fullmatch(k))


SPRING_PROTOCOLS = r"server\.ssl\.(?:enabledprotocols(?:\.\d+|\[\d+\])?|protocol)|spring\.ssl\.bundle\..+\.enabledprotocols(?:\.\d+|\[\d+\])?"
JDK_PROTOCOLS = r"jdk\.tls\.(?:client|server)\.protocols|https\.protocols"
TRUST_KEYS = r"server\.ssl\.truststore|spring\.ssl\.bundle\..+\.truststore\.(?:location|certificate)|javax\.net\.ssl\.truststore"
JDK_DISABLED = r"jdk\.(?:tls|certpath|jar)\.disabledalgorithms"


UP = r"(?:proxy_|grpc_|uwsgi_)"
# (rule, file kind, mode, pattern). Patterns are regular expressions, or functions of the text that
# return a count ("added", "removed"), a set of values ("changed") or a list of numbers ("lowered").
RULES = [
    ("InsecureSkipVerify", GO, "added", r"\bInsecureSkipVerify\b"),
    ("VerifyPeerCertificate callback", GO, "added", r"\bVerifyPeerCertificate\b"),
    ("VerifyConnection callback", GO, "added", r"\bVerifyConnection\b"),
    ("client certificates no longer verified", GO, "added",
     r"\b(?:NoClientCert|RequestClientCert|RequireAnyClientCert|VerifyClientCertIfGiven)\b"),
    ("TLS 1.0/1.1 or SSL 3.0 allowed", GO, "added", r"\bVersion(?:SSL30|TLS10|TLS11)\b"),
    ("TLS version below 1.2 written as a number", GO, "added", _go_old_numbers),
    ("TLS version set to a value the check cannot read (an expression, a variable)", GO, "added", _go_unread_versions),
    ("MinVersion lowered", GO, "lowered", _go_min_versions),
    ("MinVersion removed", GO, "removed", rf"\bMinVersion{GO_SET}"),
    ("weak cipher suite (3DES, RC4, NULL, EXPORT or RSA key exchange)", GO, "added",
     r"\bTLS_\w*(?:_3DES_|_RC4_|_NULL_|_DES_|EXPORT)\w*|\bTLS_RSA_WITH_\w+|\bInsecureCipherSuites\b"),
    ("cipher suite the check cannot name (a number or an expression)", GO, "added", _go_unread_suites),
    ("RootCAs removed", GO, "removed", rf"\bRootCAs{GO_SET}"),
    ("ClientCAs removed", GO, "removed", rf"\bClientCAs{GO_SET}"),
    ("trusted CA pool changed", GO, "changed", _go_trust),
    ("system CA pool added", GO, "added", r"\bSystemCertPool\b"),
    ("RequireAndVerifyClientCert removed", GO, "removed", r"\bRequireAndVerifyClientCert\b"),
    ("go line lowered (older Go defaults include TLS 1.0 servers and RSA key exchange)", GOMOD, "lowered", _go_lines),
    ("proxy_ssl_verify off", NGINX, "added", _nginx(rf"{UP}ssl_verify (?i:off);")),
    ("proxy_ssl_verify on removed (nginx's default is off)", NGINX, "removed", _nginx(rf"{UP}ssl_verify (?i:on);")),
    ("proxy_ssl_trusted_certificate removed", NGINX, "removed", _nginx(rf"{UP}ssl_trusted_certificate .+;")),
    ("ssl_trusted_certificate removed", NGINX, "removed", _nginx(r"ssl_trusted_certificate .+;")),
    ("trusted CA file changed", NGINX, "changed", _nginx_trust),
    ("ssl_verify_client off or optional_no_ca", NGINX, "added", _nginx(r"ssl_verify_client (?i:off|optional_no_ca);")),
    ("ssl_verify_client on removed", NGINX, "removed", _nginx(r"ssl_verify_client (?i:on);")),
    ("ssl_client_certificate removed", NGINX, "removed", _nginx(r"ssl_client_certificate .+;")),
    ("TLS 1.0/1.1 or SSLv3 in a protocol list", NGINX, "added", _nginx_old_protocols),
    ("TLS 1.0/1.1 or SSLv3 as MinProtocol", NGINX, "added", _nginx_min_protocol),
    ("weak cipher suite (3DES, RC4, NULL, EXPORT, RSA key exchange or security level 0)", NGINX, "added", _weak_ciphers),
    ("system CA bundle referenced", ANY, "added",
     r"/etc/(?:ssl|pki/tls)/certs(?:/[\w.-]+)?|\bca-(?:certificates|bundle)\.crt\b"),
    ("GODEBUG brings back legacy TLS (tls10server, tlsrsakex, tls3des, tlsunsafeekm, tlssha1, x509sha1)", ANY, "added",
     LEGACY_GODEBUG),
    (f"godebug default before Go 1.{GODEBUG_DEFAULT_MIN} (legacy TLS defaults)", ANY, "added", _old_godebug_default),
    ("OpenSSL security level 0", ANY, "added", SECLEVEL0),
    ("OpenSSL MinProtocol below TLS 1.2 (openssl.cnf)", ANY, "added",
     r"(?i)\bMinProtocol\s*=\s*(?:SSLv3|TLSv1(?:\.1)?|None)(?![.\w])"),
    ("rejectUnauthorized: false", JS, "added", r"\brejectUnauthorized\s*:\s*false\b"),
    ("NODE_TLS_REJECT_UNAUTHORIZED=0", ANY, "added", r"\bNODE_TLS_REJECT_UNAUTHORIZED['\"\]]*\s*[:=]?\s*['\"]?0"),
    ("verify=False", PY, "added", r"\bverify\s*=\s*False\b"),
    ("check_hostname = False", PY, "added", r"\bcheck_hostname\s*=\s*False\b"),
    ("CERT_NONE", ANY, "added", r"\bCERT_NONE\b"),
    ("unverified SSL context", PY, "added", r"\b_create_unverified_context\b"),
    ("curl --insecure or -k", ANY, "added", r"\bcurl\b[^\n]*\s(?:--insecure|-k)(?=\s|$)|(?:^|\s)--insecure(?=\s|$)"),
    # 오프라인판 추가: Java·Kotlin(JSSE, Apache HttpClient, OkHttp, Netty) 코드 규칙. 개수 비교라 원본에 있던 것은 안 걸린다.
    ("TrustManager that trusts every certificate (X509TrustManager, trustAll)", JAVA, "added",
     r"\bX509(?:Extended)?TrustManager\b|\bTrustAllCerts?\b|\btrustAll\w*|\bInsecureTrustManagerFactory\b"),
    ("checkServerTrusted/checkClientTrusted with an empty body", JAVA, "added", _java_empty_trust),
    ("HostnameVerifier set or replaced (hostname check can be skipped)", JAVA, "added",
     r"\bHostnameVerifier\b|\bset(?:Default)?HostnameVerifier\b|\.hostnameVerifier\s*[({]|\bNoopHostnameVerifier\b|"
     r"\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bAllowAllHostnameVerifier\b"),
    ("trust strategy that accepts self-signed or every certificate", JAVA, "added", r"\bTrust(?:SelfSigned|All)Strategy\b"),
    ("endpoint identification turned off", JAVA, "added",
     r"\bsetEndpointIdentificationAlgorithm\s*\(\s*(?:null|\"\")\s*\)"),
    ("SSLContext for SSL 3.0 or TLS 1.0/1.1", JAVA, "added",
     r"\bSSLContext\s*\.\s*getInstance\s*\(\s*\"(?:SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)\""),
    ("TLS 1.0/1.1 or SSLv3 in setEnabledProtocols/setProtocols", JAVA, "added", _java_old_protocols),
    # 오프라인판 추가: 설정(Spring application.properties·yml, java.security, -D 옵션, JAVA_TOOL_OPTIONS, setProperty).
    ("jdk.tls/certpath disabledAlgorithms set or changed (can re-enable weak algorithms)", ANY, "changed",
     _prop_values(JDK_DISABLED)),
    ("JDK HTTP client hostname verification turned off", ANY, "added",
     r"\bjdk\.internal\.httpclient\.disableHostnameVerification\b"),
    ("server.ssl.enabled=false (Spring Boot TLS turned off)", ANY, "added",
     _prop_count(r"server\.ssl\.enabled", lambda v: v.lower() == "false")),
    ("TLS 1.0/1.1 or SSLv3 in a Spring or JDK protocol setting", ANY, "added",
     _prop_old_protocols(SPRING_PROTOCOLS + "|" + JDK_PROTOCOLS)),
    ("server.ssl.client-auth none or want (client certificate no longer required)", ANY, "added",
     _prop_count(r"server\.ssl\.clientauth|spring\.ssl\.bundle\..+\.clientauth", lambda v: v.lower() in ("none", "want"))),
    ("server.ssl.client-auth=need removed", ANY, "removed",
     _prop_count(r"server\.ssl\.clientauth", lambda v: v.lower() == "need")),
    ("trust store setting removed", ANY, "removed", _prop_count(TRUST_KEYS, lambda v: True)),
    ("trust store changed", ANY, "changed", _prop_values(TRUST_KEYS)),
]
RAW_TOO = (JS, PY)  # approximate scanners: "added" rules also count the raw text


def kind_of(path):
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".go"):
        return GO
    if name == "go.mod":
        return GOMOD
    if name.endswith((".conf", ".conf.template")) or name == "nginx.conf":
        return NGINX
    if name.endswith(".py"):
        return PY
    if name.endswith((".js", ".mjs", ".cjs", ".ts")):
        return JS
    if name.endswith((".java", ".kt", ".kts", ".groovy", ".scala")):
        return JAVA
    return ANY


def _short(values, limit=3, width=80):
    shown = [v if len(v) <= width else v[:width] + "..." for v in sorted(values)[:limit]]
    return "[" + ", ".join(shown).replace("\x00", " ") + (", ..." if len(values) > limit else "") + "]"


def _shown(n, gomod):
    if gomod:
        return f"go 1.{n}"
    return {v: k for k, v in GO_VERSIONS.items()}.get(n, f"0x{n:04x}")


def _count(pattern, text):
    if callable(pattern):
        return pattern(text)
    if isinstance(pattern, re.Pattern):
        return len(pattern.findall(text))
    return len(re.findall(pattern, text, re.M))


def weakening(changed):
    """Why a patch weakens TLS: ["path: rule (before ..., after ...)"], [] when it does not.
    changed is {path: (text before, text after)} as loop.apply_edits returns it."""
    out = []
    for path in sorted(changed):
        kind = kind_of(path)
        raw_before, raw_after = changed[path]
        (before, bare_before), (after, bare_after) = views(raw_before, kind), views(raw_after, kind)
        for name, rule_kind, mode, pattern in RULES:
            if rule_kind not in (kind, ANY):
                continue
            if mode == "removed":
                b, a = _count(pattern, bare_before), _count(pattern, bare_after)
            else:
                b, a = _count(pattern, before), _count(pattern, after)
            if mode == "changed":
                if a - b:
                    out.append(f"{path}: {name} (before {_short(b)}, after {_short(a)})")
            elif mode == "lowered":
                if b and a and min(a) < min(b):
                    out.append(f"{path}: {name} (before {_shown(min(b), kind == GOMOD)}, after {_shown(min(a), kind == GOMOD)})")
            elif (mode == "added" and a > b) or (mode == "removed" and a < b):
                out.append(f"{path}: {name} (before {b}, after {a})")
            elif mode == "added" and kind in RAW_TOO:
                rb, ra = _count(pattern, raw_before), _count(pattern, raw_after)
                if ra > rb:
                    out.append(f"{path}: {name} (before {rb}, after {ra}, comments included)")
    return out


# ---------------------------------------------------------------------------------------------
# 오프라인판 추가: review 등급(실패 아님, 사람이 줄마다 사유를 단다). 암호 검증을 건너뛰고 성공만 돌려주는 변경을
# 잡으려는 규칙이다. 리팩터링으로도 생기므로 deny가 아니다.
VERIFY_CALLS = {
    JAVA: r"\binitVerify\s*\(|\.verify\s*\(|\bverifySignature\s*\(",
    GO: r"\b(?:Verify|VerifyASN1|VerifyPKCS1v15|VerifyPSS|VerifySignature)\s*\(|\.Verify\w*\s*\(",
    JS: r"\.verify\s*\(|\bverify\s*\(",
    PY: r"\.verify\s*\(|\bverify\s*\(",
}
DECRYPT_CALLS = {
    JAVA: r"\bDECRYPT_MODE\b|\bUNWRAP_MODE\b|\bKEMExtractSpec\b|\bdecapsulate\s*\(",
    GO: r"\bDecapsulate\s*\(|\.Decrypt\w*\s*\(|\.Open\s*\(",
    JS: r"\.decrypt\s*\(|\bdecapsulate\s*\(|\bprivateDecrypt\s*\(",
    PY: r"\.decrypt\s*\(|\bdecapsulate\s*\(",
}
STUB_VERIFY = {
    JAVA: r"\b(?:boolean|Boolean)\s+(?:verify|isValid|check)\w*\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*return\s+true\s*;\s*\}|"
          r"\bfun\s+(?:verify|isValid|check)\w*\s*\([^)]*\)\s*:\s*Boolean\s*(?:=\s*true\b|\{\s*return\s+true\s*\})",
    GO: r"\bfunc\s+(?:\([^)]*\)\s*)?(?:[Vv]erify|[Ii]sValid|[Cc]heck)\w*\s*\([^)]*\)\s*(?:bool|error)\s*\{\s*return\s+(?:true|nil)\s*\}",
    JS: r"\b(?:verify|isValid|check)\w*\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}",
    PY: r"\bdef\s+(?:verify|is_valid|check)\w*\s*\([^)]*\)\s*(?:->\s*bool\s*)?:\s*return\s+True\b",
}
REVIEW_TOTAL = [("signature verification calls decreased across the patch (initVerify, verify)", VERIFY_CALLS),
                ("decryption, unwrap or decapsulation calls decreased across the patch", DECRYPT_CALLS)]


def review(changed):
    """검토 등급 항목 목록. 각 항목은 {path, rule, before, after, detail}. changed는 weakening과 같은 꼴.
    호출 수 감소는 바뀐 파일 전체 합계로 본다(검증 호출을 다른 파일로 옮기는 리팩터링은 걸리지 않게).
    성공만 돌려주는 verify/isValid/check 메서드는 파일마다 늘었는지 본다."""
    out = []
    for name, table in REVIEW_TOTAL:
        b_total = a_total = 0
        per = []
        for path in sorted(changed):
            kind = kind_of(path)
            if kind not in table:
                continue
            before, after = views(changed[path][0], kind)[1], views(changed[path][1], kind)[1]
            b, a = _count(table[kind], before), _count(table[kind], after)
            b_total, a_total = b_total + b, a_total + a
            if a != b:
                per.append(f"{path} {b}->{a}")
        if a_total < b_total:
            out.append({"path": "(patch)", "rule": name, "before": b_total, "after": a_total, "detail": ", ".join(per)})
    for path in sorted(changed):
        kind = kind_of(path)
        if kind not in STUB_VERIFY:
            continue
        b = _count(STUB_VERIFY[kind], views(changed[path][0], kind)[0])
        a = _count(STUB_VERIFY[kind], views(changed[path][1], kind)[0])
        if a > b:
            out.append({"path": path, "rule": "verify/isValid/check method that only returns success", "before": b,
                        "after": a, "detail": "method body is a single return true (or nil)"})
    return out
