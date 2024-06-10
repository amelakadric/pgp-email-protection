$(document).ready(function() {
    let selector = null;
    $("#alt_input1").addClass("collapse");
    $("#alt_input2").addClass("collapse");
    $("#input_type").change(function(){
        selector = ".input_" + $(this).val();
        $("#alt_input1").collapse("hide");
        $("#alt_input2").collapse("hide");
        if (selector === ".input_text") $("#alt_input1").collapse("show");
        else $("#alt_input2").collapse("show");
    }); $("#alt_input1").collapse("show");

    $("#encr_message").click(function() {

        let site_url = "http://localhost:5000"

        let formdata1 = {
            enc_msg: $("#enc_msg").is(':checked'),
            sign: $("#sign").is(":checked"),
            compress: $("#compress").is(":checked"),
            radix64: $("#radix64").is(":checked"),
            text: $("#input_of_type_textarea").val(),
            file: $("#input_of_type_file")[0].files[0],
            text_or_file: $("#input_type").val()
        };

        let formdata2 = {
            type: "POST",
            contentType: "application/json",
            headers: {                                  
                'Accept': 'application/json',
                'Content-Type': 'application/json' 
            },
            data: JSON.stringify(formdata1),
            dataType: 'json',
            url: site_url + "/encr_api",
            success: function(data) {
                console.log(JSON.stringify(data));
            }
        };
        $.ajax(formdata2);
    });
});