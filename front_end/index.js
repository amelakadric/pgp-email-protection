 window.addEventListener('load', function () {
    $(".alt_input").addClass("collapse");
    $("#input_type").change(function(){
        let selector = ".input_" + $(this).val();
    
        $(".alt_input").collapse("hide");

        $(selector).collapse("show");
    });
    $(".input_text").collapse("show");
})