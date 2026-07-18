use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { Admin, Operator, Viewer }
impl Role { pub fn parse(s: &str) -> Option<Self> { match s { "admin" => Some(Self::Admin), "operator" => Some(Self::Operator), "viewer" => Some(Self::Viewer), _ => None } } pub fn as_str(self) -> &'static str { match self { Self::Admin=>"admin", Self::Operator=>"operator", Self::Viewer=>"viewer" } } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission { ProxyHostsRead, ProxyHostsWrite, CertificatesRead, CertificatesWrite, UsersManage, RolesManage }
pub fn allowed(role: Role, permission: Permission) -> bool { match permission { Permission::ProxyHostsRead|Permission::CertificatesRead => true, Permission::ProxyHostsWrite|Permission::CertificatesWrite => matches!(role, Role::Admin|Role::Operator), Permission::UsersManage|Permission::RolesManage => matches!(role, Role::Admin) } }
