﻿using System.ComponentModel;

namespace WebAPI.Models.Enums;

public enum Race
{
    [Description("Black")] Black,
    [Description("White")] White,
    [Description("Indian")] Indian,
    [Description("Coloured")] Coloured,
    [Description("Asian")] Asian
}