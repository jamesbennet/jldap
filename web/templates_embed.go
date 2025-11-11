package web

import (
	"embed"
)

// uiTemplatesFS embeds the UI templates into the binary so we don't depend
// on files under web/templates being present at runtime or on the process
// working directory.
//
// The paths here are relative to this package directory (web/).
// That means the actual files must live at:
//
//	web/templates/ui.html
//	web/templates/userForm.html
//	web/templates/groupForm.html
//
//go:embed templates/ui.html templates/userForm.html templates/groupForm.html
var uiTemplatesFS embed.FS
