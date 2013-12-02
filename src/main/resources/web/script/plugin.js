
(function ($, dm4c) {

    dm4c.add_plugin('org.deepamehta.sign-on', function () {

        dm4c.add_listener("init_3", function() {

            if (!isLoggedIn()) {
                var $sign_on = jQuery('<a href="/sign-on" id="sign-on-button">Sign on</a>')
                jQuery($sign_on).insertBefore("#login-widget a")
                jQuery('<span>&nbsp;</span>').insertAfter('#sign-on-button')
            }

                function isLoggedIn() {
                    var requestUri = '/accesscontrol/user'
                    //
                    var response = false
                    $.ajax({
                        type: "GET", url: requestUri,
                        dataType: "text", processData: true, async: false,
                        success: function(data, text_status, jq_xhr) {
                            if (typeof data === "undefined") return false
                            if (data != "") response = true
                        },
                        error: function(jq_xhr, text_status, error_thrown) {
                            console.log("Error performing GET request.. ")
                            response = false
                        }
                    })

                    return response
                }
        })

        // === Access Control Listeners ===

        dm4c.add_listener("logged_in", function(username) {
            console.log("Sign-on plugin recevied LOGIN - removing sign-up-button")
            jQuery('#sign-up-button').remove()
        })

        dm4c.add_listener("logged_out", function() {
            if (jQuery('#sign-up-button').length <= 0) {
                var $sign_on = jQuery('<a href="/sign-on" id="sign-on-button">Sign on</a>')
                jQuery($sign_on).insertBefore("#login-widget a")
                jQuery('<span>&nbsp;</span>').insertAfter('#sign-on-button')
            } else {
                console.log("Sign-on button already present .. NO CHANGE")
            }
        })
    })

}(jQuery, dm4c))
