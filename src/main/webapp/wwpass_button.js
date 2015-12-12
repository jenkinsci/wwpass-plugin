//----------------JS function called when login button is clicked----------------------------------
function token_auth(sp_name) {
    wwpass_auth(sp_name, auth_cb);
}

function associate(sp_name, path) {
    var form = document.createElement("form");
    form.setAttribute("method", "post");
    form.setAttribute("action", path);
    form.setAttribute("id", "wwpass_form");

    var hiddenField = document.createElement("input");
    hiddenField.setAttribute("type", "hidden");
    hiddenField.setAttribute("name", "ticket");
    hiddenField.setAttribute("id", "ticket");
    hiddenField.setAttribute("value", " ");
    form.appendChild(hiddenField);

    document.body.appendChild(form);

    wwpass_auth(sp_name, auth_cb);
}

//-------------- Callback JS function to get ticket or error ---------------------------------------
function auth_cb(status, ticket_or_reason) {
    if (status == WWPass_OK) { //If ticket request handled successfully
        set_ticket(ticket_or_reason);
        document.getElementById('wwpass_form').submit();
    } 
}

//--------------JS function to set the hidden parameter "puid"-------------------------------------
function set_ticket(ticket) {
    document.getElementsByName('ticket').innerHTML = ticket;
    document.getElementById("ticket").setAttribute("value", ticket);
}

