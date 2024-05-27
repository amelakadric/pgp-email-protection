
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

        console.log("encrypt"); console.log($("#encrypt").is(":checked"));
        console.log("sign"); console.log($("#sign").is(":checked"));
        console.log("compress"); console.log($("#compress").is(":checked"));
        console.log("radix64"); console.log($("#radix64").is(":checked"));
        console.log("text"); console.log($("#input_of_type_textarea").val());
        console.log("file"); console.log($("#input_of_type_file")[0].files[0]);
        console.log("text_or_file"); console.log($("#input_type").val());

        $.ajax({
            url: "http:localhost:5000/",
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
            success: function(data){ console.log(JSON.stringify(data)); },
            error: function(errMsg) {
                console.log( JSON.stringify(errMsg) );
            }
        });

    });

});