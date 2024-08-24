package logger

type Mode string

const (
	DevMode  Mode = "dev"
	ProdMode Mode = "prod"
)

func (m Mode) String() string {
	return string(m)
}

func ParseMode(mode string) Mode {
	switch mode {
	case DevMode.String():
		return DevMode
	case ProdMode.String():
		return ProdMode
	default:
		return ProdMode
	}
}

func ConvertLoggerMode(mode Mode) LogLevel {
	switch mode {
	case DevMode:
		return LevelDebug
	case ProdMode:
		return LevelInfo
	default:
		return LevelInfo
	}
}
