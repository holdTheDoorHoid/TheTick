
// Escape a value for insertion into HTML. Log lines contain data read off the
// reader wire and values supplied over HTTP, so nothing from the device is
// treated as markup.
function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

function not_tick() {
    $.get("/mugga.txt", function (data) {
        if (data.trim() === "1") {
            $('.fa-spider').addClass('fa-horse-head').removeClass('fa-spider');
            $('.sidebar-brand-text')[0].innerHTML = "The Horse";
            document.title = document.title.replaceAll('Tick', 'Horse');
        }
    });
}

function get_editor_files_list() {
    $.get("/list?dir=/", function (data) {
        data.forEach(f => {
            $("<a>")
                .addClass("collapse-item")
                .attr("href", "/editor.html?file=" + encodeURIComponent(f.name))
                .text(f.name)
                .insertAfter("#config-menu");
        });
    });
}


function remove_menu_option(name) {
    $('#menu_' + name).remove();
}

function get_version_info() {
    return $.getJSON("/version?epoch=" + Date.now(), function (data) {
        let configuration = data;

        if (configuration['features'].indexOf('wiegand') == -1)
            remove_menu_option('mode_wiegand');

        if (configuration['features'].indexOf('clockanddata') == -1)
            remove_menu_option('mode_clockanddata');

        if (configuration['features'].indexOf('ota_http') == -1)
            remove_menu_option('update');

        const MODE_LABELS = {
            'wiegand': 'Wiegand',
            'clockanddata': 'Clock&Data',
            'osdp_pd': 'OSDP PD',
            'osdp_cp': 'OSDP CP',
            'disabled': 'Disabled'
        };
        $('#menu_current_mode').text(MODE_LABELS[configuration['mode']] || configuration['mode']);

        $('#menu_version').text(configuration['version']);
        $('#menu_board_name').text(configuration['log_name'] + '-' + configuration['ChipID']);

        // The web interface is only password protected once both a username
        // and a password are set. Say so rather than letting it look secured.
        if (configuration['auth'] === false) {
            $('#auth_warning').remove();
            $('<div id="auth_warning" class="alert alert-warning m-2" role="alert">')
                .text('No web password set - this interface is open to anyone who can reach it.')
                .prependTo('#content');
        }


        console.log(data);
    });
}

function get_epochs(lines) {
    let epochs = {};
    lines.forEach(line => {
        let parts = line.split("; ");
        if (parts[2] == "epoch") {
            epochs[parts[0]] = parseInt(parts[3]) - parseInt(parts[1]);
        }
    });
    return epochs;
}

function get_epoch_time(epochs, epoch, timestamp) {
    if (epoch in epochs) {
        let date = new Date(epochs[epoch] + parseInt(timestamp))
        return date.toLocaleString()
    } else {
        return "BC: " + epoch + " TS: " + timestamp;
    }
}

$(document).ready(function () {
    get_version_info();
    not_tick();
    get_editor_files_list();
});