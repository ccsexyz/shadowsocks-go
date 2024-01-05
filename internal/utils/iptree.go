package utils

import (
	"encoding/binary"
	"net"
	"sync"
)

var ipNodePool sync.Pool

func init() {
	ipNodePool.New = func() interface{} {
		return &ipNode{}
	}
}

// IPTree implements radix tree for IP tree
type IPTree struct {
	root *ipNode
}

// NewIPTree creates IP tree
func NewIPTree() *IPTree {
	tree := &IPTree{}
	tree.root = allocNewIPNode()
	return tree
}

type ipNode struct {
	left  *ipNode
	right *ipNode
	hit   bool
}

func allocNewIPNode() *ipNode {
	return ipNodePool.Get().(*ipNode)
}

func freeIPNode(node *ipNode) {
	node.hit = false
	node.left = nil
	node.right = nil
	ipNodePool.Put(node)
}

const (
	startMask = uint32(0x80000000)
	maxIPLen  = 32
)

func (tree *IPTree) insert(ip uint32, maskLen int) {
	mask := startMask
	if maskLen > maxIPLen {
		maskLen = maxIPLen
	}
	parents := make([]*ipNode, 0, 32)
	root := tree.root
	for mask > 0 && maskLen > 0 {
		parents = append(parents, root)
		if ip&mask != 0 {
			if root.right == nil {
				root.right = allocNewIPNode()
			}
			root = root.right
		} else {
			if root.left == nil {
				root.left = allocNewIPNode()
			}
			root = root.left
		}
		mask >>= 1
		maskLen--
		if maskLen == 0 {
			root.hit = true
		}
	}
	for it := len(parents) - 1; it >= 0; it-- {
		parent := parents[it]
		if parent.left != nil && parent.right != nil &&
			parent.left.hit == true && parent.right.hit == true {
			parent.hit = true
			freeIPNode(parent.left)
			freeIPNode(parent.right)
			parent.left = nil
			parent.right = nil
		}
	}
}

func (tree *IPTree) test(ip uint32) bool {
	mask := startMask
	root := tree.root
	for mask > 0 {
		if root.hit {
			return true
		}
		if ip&mask != 0 {
			root = root.right
		} else {
			root = root.left
		}
		if root == nil {
			return false
		}
		mask >>= 1
	}
	return true
}

// InsertIP inserts an IP to the tree
func (tree *IPTree) InsertIP(ip net.IP) {
	ip = ip.To4()
	tree.insert(binary.BigEndian.Uint32(ip), 32)
}

// InsertIPNet inserts an ipnet to the tree, eg: 127.0.0.1/24
func (tree *IPTree) InsertIPNet(ipnet *net.IPNet) {
	ip := ipnet.IP.To4()
	ones, _ := ipnet.Mask.Size()
	tree.insert(binary.BigEndian.Uint32(ip), ones)
}

// Insert inserts a CIDR string or an ip string to the tree
func (tree *IPTree) Insert(s string) {
	ip := net.ParseIP(s)
	if ip != nil {
		tree.InsertIP(ip)
		return
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return
	}
	tree.InsertIPNet(ipnet)
	return
}

// Test test whether an IP string is in the tree
func (tree *IPTree) Test(s string) bool {
	ip := net.ParseIP(s)
	if ip != nil {
		return tree.TestIP(ip)
	}
	return false
}

// TestIP test whether an net.IP is in the tree
func (tree *IPTree) TestIP(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return tree.test(binary.BigEndian.Uint32(ip))
}
