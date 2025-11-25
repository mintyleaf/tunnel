package ipam

import (
	"database/sql"
	"fmt"
	"log"
	"net"

	_ "github.com/lib/pq"
)

type IPAMService struct {
	DB          *sql.DB
	NetworkCIDR string
}

type IPState struct {
	ID              int
	NetworkCIDR     string
	NextAvailableIP string
}

const singleRowID = 1

func InitTables(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_state (
			id INTEGER PRIMARY KEY,
			network_cidr TEXT NOT NULL,
			next_available_ip TEXT NOT NULL
		);
	`)
	return err
}

func (s IPAMService) ServerAddr() (string, error) {
	ip, _, err := net.ParseCIDR(s.NetworkCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR format: %w", err)
	}

	return incrementIP(ip).String(), nil
}

func (s IPAMService) InitializeNetwork() error {
	ip, _, err := net.ParseCIDR(s.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	firstUsableIP := incrementIP(ip)

	tx, err := s.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			log.Printf("transaction rolled back due to error: %v", err)
		} else {
			err = tx.Commit()
			if err != nil {
				log.Printf("failed to commit transaction: %v", err)
			}
		}
	}()

	_, err = tx.Exec("DELETE FROM ip_state WHERE id = $1", singleRowID)
	if err != nil {
		return fmt.Errorf("delete old state: %w", err)
	}

	_, err = tx.Exec(`INSERT
			INTO ip_state
			(id, network_cidr, next_available_ip)
			VALUES
			($1, $2, $3)`,
		singleRowID, s.NetworkCIDR, firstUsableIP.String())
	if err != nil {
		return fmt.Errorf("insert new state: %w", err)
	}

	return nil
}

func (s IPAMService) NextIP() (string, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return "", fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	var currentIPStr string
	var currentCIDR string

	row := tx.QueryRow(`SELECT
			next_available_ip, network_cidr
			FROM
			ip_state
			WHERE id = $1
			FOR UPDATE`,
		singleRowID)
	err = row.Scan(&currentIPStr, &currentCIDR)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("network not initialized")
	} else if err != nil {
		return "", fmt.Errorf("read current IP: %w", err)
	}

	currentIP := net.ParseIP(currentIPStr)
	_, ipNet, err := net.ParseCIDR(currentCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid stored CIDR (%s): %w", currentCIDR, err)
	}

	if currentIP == nil || !ipNet.Contains(currentIP) || isBroadcast(currentIP, ipNet) {
		return "", fmt.Errorf(
			"network exhaustion: next IP (%s) is outside of CIDR range (%s) or is the broadcast address",
			currentIPStr, currentCIDR,
		)
	}

	allocatedIP := currentIP
	nextIPToStore := incrementIP(currentIP)

	_, err = tx.Exec(`UPDATE
			ip_state
			SET
			next_available_ip = $1
			WHERE id = $2`,
		nextIPToStore.String(), singleRowID)
	if err != nil {
		return "", fmt.Errorf("update next IP: %w", err)
	}

	return allocatedIP.String(), nil
}

func (s IPAMService) JoinIPAndNet(ip string) (string, error) {
	_, ipNet, err := net.ParseCIDR(s.NetworkCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR (%s): %w", s.NetworkCIDR, err)
	}
	size, _ := ipNet.Mask.Size()

	return fmt.Sprintf("%s/%d", ip, size), nil
}

func incrementIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}

func isBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < len(ip4); i++ {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	return ip4.Equal(broadcast)
}
