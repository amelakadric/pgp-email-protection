$(document).ready(function() {
 window.addEventListener('load', function () {
    let selector = null;
    $("#alt_input1").addClass("collapse");
    $("#alt_input2").addClass("collapse");
    $("#input_type").change(function(){
        selector = ".input_" + $(this).val();
        $("#alt_input1").collapse("hide");
        $("#alt_input2").collapse("hide");
        if (selector == "text") $("#alt_input1").collapse("show");
        else $("#alt_input2").collapse("show");
    }); $("#alt_input1").collapse("show");

    $("#encr_message").click(function() {

        let site_url = "http://192.168.0.27:5000"

        console.log($SCRIPT_ROOT)

        $.ajax({
            url: site_url + "/",
            method: "POST",        
            data: { 
                encrypt: $("#encrypt").is(':checked'),
                sign: $("#sign").is(":checked"),
                compress: $("#compress").is(":checked"),
                radix64: $("#radix64").is(":checked"),
                text: $("textarea#input_of_type_textarea").val(),
                file: $("#input_of_type_file")[0].files[0],
                text_or_file: $("#input_type").val()
            }, 
            contentType: false,
            cache: false,
            processData: false,
            dataType: 'json',
            success: function(data){ alert("success"); console.log(JSON.stringify(data)); },
            error: function(errMsg) {
                console.log(  JSON.stringify(errMsg) );
            }
        });


        site_url = "http://127.0.0.1:5000/"

        $.getJSON(site_url + "//encr_api", {
            encrypt: $("#encrypt").is(':checked'),
            sign: $("#sign").is(":checked"),
            compress: $("#compress").is(":checked"),
            radix64: $("#radix64").is(":checked"),
            text: $("textarea#input_of_type_textarea").val(),
            file: $("#input_of_type_file")[0].files[0],
            text_or_file: $("#input_type").val()
        }, function(data){
            alert(data)
        });


    });

    });
});