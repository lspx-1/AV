using System.Globalization;
using System.Text;

namespace Bastion.Core.Signatures;

public sealed class RuleParseException(string message, int line) : Exception($"Zeile {line}: {message}")
{
    public int Line { get; } = line;
}

/// <summary>
/// Parses a YARA-compatible subset: rule names and tags, <c>meta</c>, text strings with
/// <c>ascii</c>/<c>wide</c>/<c>nocase</c>, hex strings with <c>??</c> wildcards, and conditions
/// using and/or/not, parentheses, <c>$id</c>, <c>any|all|N of them|(...)</c>, <c>is_pe</c> and <c>filesize</c>.
/// </summary>
public static class RuleParser
{
    public static List<Rule> Parse(string source)
    {
        var tokens = new Lexer(source).Tokenize();
        var p = new Parser(tokens);
        var rules = new List<Rule>();
        while (!p.AtEnd)
            rules.Add(p.ParseRule());
        return rules;
    }

    private enum T { Ident, Str, Num, Hex, Sym, End }

    private sealed record Token(T Type, string Text, int Line);

    private sealed class Lexer(string s)
    {
        private int _i;
        private int _line = 1;

        public List<Token> Tokenize()
        {
            var list = new List<Token>();
            var expectHex = false;
            while (true)
            {
                SkipTrivia();
                if (_i >= s.Length)
                {
                    list.Add(new Token(T.End, "", _line));
                    return list;
                }
                var c = s[_i];
                if (c == '{' && expectHex)
                {
                    var end = s.IndexOf('}', _i);
                    if (end < 0) throw new RuleParseException("Hex-String ohne }", _line);
                    list.Add(new Token(T.Hex, s[(_i + 1)..end], _line));
                    _line += s[_i..end].Count(ch => ch == '\n');
                    _i = end + 1;
                    expectHex = false;
                    continue;
                }
                expectHex = false;
                if (c == '"')
                {
                    list.Add(new Token(T.Str, ReadString(), _line));
                    continue;
                }
                if (char.IsDigit(c))
                {
                    var start = _i;
                    if (c == '0' && _i + 1 < s.Length && (s[_i + 1] == 'x' || s[_i + 1] == 'X'))
                    {
                        _i += 2;
                        while (_i < s.Length && Uri.IsHexDigit(s[_i])) _i++;
                        list.Add(new Token(T.Num, long.Parse(s[(start + 2).._i], NumberStyles.HexNumber, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture), _line));
                        continue;
                    }
                    while (_i < s.Length && char.IsDigit(s[_i])) _i++;
                    var number = long.Parse(s[start.._i], CultureInfo.InvariantCulture);
                    if (_i + 1 < s.Length && s[_i + 1] == 'B' && (s[_i] == 'K' || s[_i] == 'M'))
                    {
                        number *= s[_i] == 'K' ? 1024 : 1024 * 1024;
                        _i += 2;
                    }
                    list.Add(new Token(T.Num, number.ToString(CultureInfo.InvariantCulture), _line));
                    continue;
                }
                if (char.IsLetter(c) || c == '_' || c == '$')
                {
                    var start = _i++;
                    while (_i < s.Length && (char.IsLetterOrDigit(s[_i]) || s[_i] == '_' || s[_i] == '*')) _i++;
                    list.Add(new Token(T.Ident, s[start.._i], _line));
                    continue;
                }
                var two = _i + 1 < s.Length ? s.Substring(_i, 2) : "";
                if (two is "<=" or ">=" or "==" or "!=")
                {
                    list.Add(new Token(T.Sym, two, _line));
                    _i += 2;
                    continue;
                }
                if ("{}():=,<>".Contains(c))
                {
                    list.Add(new Token(T.Sym, c.ToString(), _line));
                    // "$a = {" starts a hex string
                    expectHex = c == '=' && list.Count >= 2 && list[^2].Type == T.Ident && list[^2].Text.StartsWith('$');
                    _i++;
                    continue;
                }
                throw new RuleParseException($"Unerwartetes Zeichen '{c}'", _line);
            }
        }

        private void SkipTrivia()
        {
            while (_i < s.Length)
            {
                if (s[_i] == '\n') { _line++; _i++; }
                else if (char.IsWhiteSpace(s[_i])) _i++;
                else if (s[_i] == '/' && _i + 1 < s.Length && s[_i + 1] == '/')
                {
                    while (_i < s.Length && s[_i] != '\n') _i++;
                }
                else if (s[_i] == '/' && _i + 1 < s.Length && s[_i + 1] == '*')
                {
                    var end = s.IndexOf("*/", _i + 2, StringComparison.Ordinal);
                    end = end < 0 ? s.Length : end + 2;
                    _line += s[_i..end].Count(ch => ch == '\n');
                    _i = end;
                }
                else break;
            }
        }

        private string ReadString()
        {
            var sb = new StringBuilder();
            _i++;
            while (_i < s.Length && s[_i] != '"')
            {
                if (s[_i] == '\n') throw new RuleParseException("String ohne schließendes \"", _line);
                if (s[_i] == '\\' && _i + 1 < s.Length)
                {
                    _i++;
                    switch (s[_i])
                    {
                        case 'n': sb.Append('\n'); break;
                        case 't': sb.Append('\t'); break;
                        case 'r': sb.Append('\r'); break;
                        case 'x' when _i + 2 < s.Length:
                            sb.Append((char)Convert.ToByte(s.Substring(_i + 1, 2), 16));
                            _i += 2;
                            break;
                        default: sb.Append(s[_i]); break;
                    }
                    _i++;
                    continue;
                }
                sb.Append(s[_i++]);
            }
            _i++;
            return sb.ToString();
        }
    }

    private sealed class Parser(List<Token> tokens)
    {
        private int _p;

        public bool AtEnd => Peek.Type == T.End;
        private Token Peek => tokens[_p];
        private Token Next() => tokens[_p++];

        private bool Accept(string text)
        {
            if (Peek.Text == text && Peek.Type is T.Ident or T.Sym)
            {
                _p++;
                return true;
            }
            return false;
        }

        private Token Expect(T type, string? text = null)
        {
            var t = Next();
            if (t.Type != type || (text is not null && t.Text != text))
                throw new RuleParseException($"Erwartet {text ?? type.ToString()}, gefunden '{t.Text}'", t.Line);
            return t;
        }

        public Rule ParseRule()
        {
            Accept("private");
            Accept("global");
            Expect(T.Ident, "rule");
            var name = Expect(T.Ident).Text;
            var tags = new List<string>();
            if (Accept(":"))
            {
                while (Peek.Type == T.Ident && Peek.Text != "{")
                    tags.Add(Next().Text);
            }
            Expect(T.Sym, "{");
            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var strings = new List<RuleString>();
            RuleExpr? condition = null;
            while (!Accept("}"))
            {
                var section = Expect(T.Ident).Text;
                Expect(T.Sym, ":");
                switch (section)
                {
                    case "meta":
                        while (Peek.Type == T.Ident && tokens[_p + 1].Text == "=")
                        {
                            var key = Next().Text;
                            Next();
                            meta[key] = Next().Text;
                        }
                        break;
                    case "strings":
                        while (Peek.Type == T.Ident && Peek.Text.StartsWith('$'))
                            strings.Add(ParseString());
                        break;
                    case "condition":
                        condition = ParseOr();
                        break;
                    default:
                        throw new RuleParseException($"Unbekannter Abschnitt '{section}'", Peek.Line);
                }
            }
            return new Rule
            {
                Name = name,
                Tags = tags,
                Meta = meta,
                Strings = strings,
                Condition = condition ?? throw new RuleParseException($"Regel {name} hat keine condition", Peek.Line),
            };
        }

        private RuleString ParseString()
        {
            var id = Next().Text;
            Expect(T.Sym, "=");
            var value = Next();
            if (value.Type == T.Hex)
                return new RuleString { Id = id, Patterns = [ParseHex(value)] };
            if (value.Type != T.Str)
                throw new RuleParseException("String oder Hex-String erwartet", value.Line);

            bool ascii = false, wide = false, nocase = false;
            while (Peek.Type == T.Ident && Peek.Text is "ascii" or "wide" or "nocase" or "fullword")
            {
                switch (Next().Text)
                {
                    case "ascii": ascii = true; break;
                    case "wide": wide = true; break;
                    case "nocase": nocase = true; break;
                }
            }
            if (!wide) ascii = true;
            var text = nocase ? value.Text.ToLowerInvariant() : value.Text;
            var patterns = new List<short[]>();
            if (ascii)
                patterns.Add(text.Select(ch => (short)(byte)ch).ToArray());
            if (wide)
                patterns.Add(text.SelectMany(ch => new[] { (short)(byte)ch, (short)(ch >> 8) }).ToArray());
            return new RuleString { Id = id, Patterns = patterns, NoCase = nocase };
        }

        private static short[] ParseHex(Token token)
        {
            var clean = new string(token.Text.Where(ch => !char.IsWhiteSpace(ch)).ToArray());
            if (clean.Length % 2 != 0)
                throw new RuleParseException("Hex-String hat ungerade Länge", token.Line);
            var result = new short[clean.Length / 2];
            for (var i = 0; i < result.Length; i++)
            {
                var pair = clean.Substring(i * 2, 2);
                if (pair == "??")
                    result[i] = -1;
                else if (byte.TryParse(pair, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                    result[i] = b;
                else
                    throw new RuleParseException($"Ungültiges Hex-Byte '{pair}' (unterstützt: 00-FF und ??)", token.Line);
            }
            return result;
        }

        private RuleExpr ParseOr()
        {
            var left = ParseAnd();
            while (Accept("or"))
                left = new OrExpr(left, ParseAnd());
            return left;
        }

        private RuleExpr ParseAnd()
        {
            var left = ParseNot();
            while (Accept("and"))
                left = new AndExpr(left, ParseNot());
            return left;
        }

        private RuleExpr ParseNot() => Accept("not") ? new NotExpr(ParseNot()) : ParsePrimary();

        private RuleExpr ParsePrimary()
        {
            var t = Peek;
            if (Accept("("))
            {
                var inner = ParseOr();
                Expect(T.Sym, ")");
                return inner;
            }
            if (Accept("true")) return new ConstExpr(true);
            if (Accept("false")) return new ConstExpr(false);
            if (Accept("is_pe")) return new IsPeExpr();
            if (Accept("filesize"))
            {
                var op = Expect(T.Sym).Text;
                var number = long.Parse(Expect(T.Num).Text, CultureInfo.InvariantCulture);
                return new FileSizeExpr(op, number);
            }
            if (t.Type == T.Ident && t.Text.StartsWith('$'))
            {
                _p++;
                return new StringRefExpr(t.Text);
            }
            int quantity;
            if (Accept("any")) quantity = 1;
            else if (Accept("all")) quantity = -1;
            else if (t.Type == T.Num) { _p++; quantity = int.Parse(t.Text, CultureInfo.InvariantCulture); }
            else throw new RuleParseException($"Unerwartet in condition: '{t.Text}'", t.Line);

            Expect(T.Ident, "of");
            if (Accept("them"))
                return new OfExpr(quantity, null);
            Expect(T.Sym, "(");
            var selectors = new List<string> { Expect(T.Ident).Text };
            while (Accept(","))
                selectors.Add(Expect(T.Ident).Text);
            Expect(T.Sym, ")");
            return new OfExpr(quantity, selectors);
        }
    }
}
