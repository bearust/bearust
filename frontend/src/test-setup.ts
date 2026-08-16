import { setI18n } from "react-i18next";
import { i18n, initI18n } from "@/i18n";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

await initI18n("en");
setI18n(i18n);
