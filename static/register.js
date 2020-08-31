$("#id_username").focusout(function() {
    var username = $(this).val();

    $.ajax({
        url: '/validate_username',
        data: {
            'username': username
        },
        dataType: 'json',
        success: function(data) {
            if (data.is_taken) {
                alert(data.error_message);
                $("#id_username").val('');
            }
        }
    });
});