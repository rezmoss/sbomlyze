package output

// Format represents supported output formats
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatJUnit    Format = "junit"
	FormatMarkdown Format = "markdown"
	FormatPatch    Format = "patch"
)
