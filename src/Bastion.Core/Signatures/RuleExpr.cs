namespace Bastion.Core.Signatures;

public abstract record RuleExpr
{
    public abstract bool Evaluate(RuleEvalContext ctx);
}

public sealed record ConstExpr(bool Value) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => Value;
}

public sealed record StringRefExpr(string Id) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => ctx.IsHit(Id);
}

public sealed record AndExpr(RuleExpr Left, RuleExpr Right) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => Left.Evaluate(ctx) && Right.Evaluate(ctx);
}

public sealed record OrExpr(RuleExpr Left, RuleExpr Right) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => Left.Evaluate(ctx) || Right.Evaluate(ctx);
}

public sealed record NotExpr(RuleExpr Inner) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => !Inner.Evaluate(ctx);
}

/// <summary><c>any|all|N of them</c> or <c>N of ($a, $b*)</c>. Quantity -1 = all, 1 = any.</summary>
public sealed record OfExpr(int Quantity, IReadOnlyList<string>? Selectors) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx)
    {
        var ids = ctx.Strings.Select(s => s.Id).Where(id => Selectors is null || Selectors.Any(sel =>
            sel.EndsWith('*') ? id.StartsWith(sel[..^1], StringComparison.Ordinal) : id == sel)).ToList();
        var needed = Quantity < 0 ? ids.Count : Quantity;
        if (needed == 0)
            return true;
        var found = 0;
        foreach (var id in ids)
        {
            if (ctx.IsHit(id) && ++found >= needed)
                return true;
        }
        return false;
    }
}

public sealed record IsPeExpr : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => ctx.File.Pe is not null;
}

public sealed record FileSizeExpr(string Op, long Value) : RuleExpr
{
    public override bool Evaluate(RuleEvalContext ctx) => Op switch
    {
        "<" => ctx.File.Size < Value,
        "<=" => ctx.File.Size <= Value,
        ">" => ctx.File.Size > Value,
        ">=" => ctx.File.Size >= Value,
        "==" => ctx.File.Size == Value,
        "!=" => ctx.File.Size != Value,
        _ => false,
    };
}
