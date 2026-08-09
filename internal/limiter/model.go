package limiter

type UserInfo struct {
	UID           int
	Email         string
	SpeedLimit    uint64 // Bytes/s, 0 = unlimited
	DeviceLimit   int    // 现语义 = 并发连接上限,0 = unlimited
	ConnGroup     string // 连接数计数分组键(同组共享配额);空 = 退化按 email 计数
	ConnStatGroup string // 展示统计分组键(实际节点);空时复用 ConnGroup
}
