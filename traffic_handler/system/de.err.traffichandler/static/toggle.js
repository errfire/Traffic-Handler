    document.addEventListener('DOMContentLoaded', function () {
        var constructionRows = document.querySelectorAll('.construction-row');
        constructionRows.forEach(function (row) {
            row.addEventListener('click', function () {
                var constructionId = row.getAttribute('data-construction-id');

                var modal = new bootstrap.Modal(document.getElementById('constructionModal' + constructionId));
                modal.show();
            });
        });
        var closeButtons = document.querySelectorAll('.modal .close, .modal .btn-danger');

        closeButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                var modal = bootstrap.Modal.getInstance(button.closest('.modal'));
                modal.hide();
            });
        });
    });