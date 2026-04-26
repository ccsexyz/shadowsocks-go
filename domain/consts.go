package domain

const (
	TypeIPv4 = 1
	TypeDm   = 3
	TypeIPv6 = 4
	TypeMux  = 0x6D
	TypeTs   = 0x74
	TypeNop  = 0x90

	LenIPv4 = 4
	LenIPv6 = 16
	LenTs   = 8

	MuxAddr = "mux:12580"
	MuxHost = "mux"
	MuxPort = 12580

	VerSocks4     = 4
	VerSocks5     = 5
	VerSocks6     = 6
	CmdConnect    = 1
	CmdUDP        = 3
	CmdSocks4OK   = 0x5A
	VerSocks4Resp = 0

	DefaultObfsHost        = "www.bing.com"
	DefaultFilterCapacity  = 100000
	DefaultFilterFalseRate = 0.00001
	DefaultTimeout         = 65
	DefaultMethod          = "aes-128-gcm"
	DefaultPassword        = "secret"
	BufferSize             = 8192
	HTTPBufferSize         = 4096
)
