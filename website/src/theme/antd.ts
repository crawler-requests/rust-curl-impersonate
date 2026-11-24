import type { ThemeConfig } from "antd";
import { fonts, layout, palette } from "./tokens";

// Ant Design inherits the site palette, so components (Table, Tag, Input)
// sit on the same paper background instead of the default blue-grey.
export const antdTheme: ThemeConfig = {
  token: {
    colorPrimary: palette.accent,
    colorInfo: palette.accent,
    colorSuccess: palette.ok,
    colorTextBase: palette.ink,
    colorText: palette.inkSoft,
    colorTextSecondary: palette.inkMuted,
    colorBgBase: palette.paper,
    colorBgContainer: palette.paper,
    colorBgElevated: palette.paperRaised,
    colorBorder: palette.line,
    colorBorderSecondary: palette.line,
    borderRadius: layout.radiusSmall,
    fontFamily: fonts.body,
    fontSize: 14,
    controlHeight: 34,
  },
  components: {
    Table: {
      headerBg: palette.paperRaised,
      headerColor: palette.ink,
      rowHoverBg: palette.accentSoft,
      borderColor: palette.line,
      cellPaddingBlock: 10,
      cellPaddingInline: 14,
    },
    Tag: {
      defaultBg: palette.paperRaised,
      defaultColor: palette.inkSoft,
    },
    Input: {
      activeBorderColor: palette.accent,
      hoverBorderColor: palette.accent,
    },
    Segmented: {
      itemSelectedBg: palette.ink,
      itemSelectedColor: palette.paper,
    },
    Tabs: {
      inkBarColor: palette.accent,
      itemSelectedColor: palette.ink,
      itemHoverColor: palette.accentInk,
    },
  },
};
