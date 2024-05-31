using System.ComponentModel;

namespace WebAPI.Models.Enums;

public enum Gender
{
    [Description("Prefer Not To Say")] PreferNotToSay,
    [Description("Male")] Male,
    [Description("Female")] Female
}