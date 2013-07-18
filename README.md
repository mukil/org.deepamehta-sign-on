# org.deepamehta Sign-on

This plugin adds a simple HTML-UI and a REST service. Together both provide the possibility to create unique "User Account"-Items, resp. "Person"-Items in DeepaMehta via the OpenID-Authentication Providers Google and Yahoo.

It is based on the [JOpenID library](https://code.google.com/p/jopenid) from [Michael Lao](http://www.liaoxuefeng.com) which is available under Apache License 2.0.

This plugin is tested to work with [DeepaMehta 4.1.1-SNAPSHOT](https://github.com/jri/deepamehta/commit/a6ded128b62959617f76955546405d96426825ca) and the [dm4-webactivator 0.3.1](https://github.com/jri/dm4-webactivator) plugin.

# Licensed under the GPL License 3.0

GPL v3 - https://www.gnu.org/licenses/gpl.html

# Release Notes

1.0-SNAPSHOT July, 18 2013

Features:
- "User Account" creation (Person=Firstname, Lastname, E-Mail User Account=Username) with Google and Yahoo is functional

Known Issues:
- creating a HTTPSession for DeepaMehta after a successfull authentication is not yet possible
- replay attack is not yet prevented (see fixmes: around "nonce")
- no configurable endpoints
- no OpenId Spec conformity

