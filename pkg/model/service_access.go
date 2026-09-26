package model

import "time"

type ServiceAccess struct {
	ID               string     `json:"id" gorm:"primaryKey;size:63"`
	UserID           uint       `json:"-" gorm:"uniqueIndex:idx_service_access_target;not null"`
	Cluster          string     `json:"cluster" gorm:"size:255;uniqueIndex:idx_service_access_target;not null"`
	Namespace        string     `json:"namespace" gorm:"size:63;uniqueIndex:idx_service_access_target;not null"`
	Kind             string     `json:"kind" gorm:"size:16;uniqueIndex:idx_service_access_target;not null"`
	Name             string     `json:"name" gorm:"size:253;uniqueIndex:idx_service_access_target;not null"`
	Port             int        `json:"port" gorm:"uniqueIndex:idx_service_access_target;not null"`
	Scheme           string     `json:"scheme" gorm:"size:5;not null"`
	Path             string     `json:"path" gorm:"type:text;not null"`
	ExpiresInMinutes int        `json:"expiresInMinutes" gorm:"not null;default:180"`
	Public           bool       `json:"public" gorm:"not null;default:false"`
	PublicUntil      *time.Time `json:"publicUntil"`
}
