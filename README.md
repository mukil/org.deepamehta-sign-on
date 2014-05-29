
# org.deepamehta Sign-on Module

A DeepaMehta 4 plugin adding a simple HTML-UI and a REST service for OpenID-Authentication and DeepaMehta 4 User Accounts. Currently this plugin only supports authentication through an existing Google or a Yahoo account.

It does so through extending the model of a DeepaMehta 4 "User Account" about an "OpenID" child type (of type Text).

This plugin is based on the [JOpenID library](https://code.google.com/p/jopenid) from [Michael Lao](http://www.liaoxuefeng.com) which is available under Apache License 2.0.

## Download & Installation

This plugin is tested to work with [DeepaMehta 4.2](https://github.com/jri/deepamehta) and depends on the installation of the [dm4-webactivator 0.4.2](https://github.com/jri/dm4-webactivator) plugin. 

You can find the latest ''dm42-sign-on-1.0.jar'' bundle to download at [http://download.deepamehta.de/nightly/](http://download.deepamehta.de/nightly/).

## Licensed under the GPL License 3.0

GPL v3 - https://www.gnu.org/licenses/gpl.html

This software is still EXPERIMENTAL and this means:

DO NOT TO USE IT UNLESS YOU KNOW WHAT YOU'RE DOING.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# Version History

1.1, UPCOMING
- Compatible with DeepaMehta 4.3

1.0, Mar 08, 2014
- basically functional
- insecure
- compatible with DeepaMehta 4.2

1.0-SNAPSHOT, Jul 18, 2013

Features:
- "User Account" creation (Person=Firstname, Lastname, E-Mail User Account=Username) with Google and Yahoo is functional

--------------------
Author: Malte Reißig

