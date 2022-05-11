# based on relayd Makefile

include $(TOPDIR)/rules.mk

PKG_NAME:=delphinusdnsd
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/delphinusdns/delphinusdnsd.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_DATE:=2022-05-08
PKG_SOURCE_VERSION:=3784dd39052835b09126d45654ce3fcdd4000a23

PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/delphinusdnsd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Delphinusdnsd Authoritative DNS Server
  URL:=https://delphinusdns.org
  USERID:=_ddd=454:_ddd=454
  DEPENDS:=+libbsd +libopenssl +librt
endef

define Package/delphinusdnsd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/delphinusdnsd/delphinusdnsd $(1)/usr/sbin/delphinusdnsd
	##$(INSTALL_DIR) $(1)/usr/bin
	##$(INSTALL_BIN) $(PKG_BUILD_DIR)/dddctl/dddctl $(1)/usr/bin/dddctl

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/delphinusdnsd.init $(1)/etc/init.d/delphinusdnsd
	
	$(INSTALL_DIR) $(1)/etc/delphinusdnsd
	$(INSTALL_DIR) $(1)/etc/delphinusdnsd/etc
	##$(INSTALL_BIN) ./files/delphinusdns.conf $(1)/etc/delphinusdnsd/etc/delphinusdns.conf
endef

CONFIGURE_ARGS := \
        --without-setproctitle \
	--location=/etc/delphinusdnsd \
	--openwrt

$(eval $(call BuildPackage,delphinusdnsd))
