// +build !redis

package ss


func newRedisFilter(_, _ string, _ int) bytesFilter {
	return newNullFilter()
}
