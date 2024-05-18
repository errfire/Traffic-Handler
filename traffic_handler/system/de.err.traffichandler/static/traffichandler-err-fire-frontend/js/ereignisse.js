$(document).ready(function() {

    $('#logTable').DataTable({
        "initComplete": function(settings, json) {
            this.api().columns().every(function() {
                var column = this;
                var header = $(column.header());
                header.append('<br><input type="text" placeholder="Filtern">');
                $('input', this.header()).on('keyup change', function() {
                    if (column.search() !== this.value) {
                        column.search(this.value).draw();
                    }
                });
            });
        }
    });
});
