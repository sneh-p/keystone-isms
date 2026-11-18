import { parseGuide } from "./help";
import guideText from "../../../docs/user-guide.md?raw";

/** The user guide and its screenshots, bundled at build time (only these images are ever shown in help). */
export const GUIDE = parseGuide(guideText);

const files = import.meta.glob<string>("../../../docs/user-guide/*.png", { eager: true, query: "?url", import: "default" });

/** Screenshot URLs by file name, for `user-guide/<name>.png` references in the guide. */
export const HELP_IMAGES: Record<string, string> = Object.fromEntries(Object.entries(files).map(([path, url]) => [path.split("/").pop() as string, url]));
