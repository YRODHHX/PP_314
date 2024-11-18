const table = $('#usersTable');
tableOfAllUsers();

function tableOfAllUsers() {
    table.empty()
    fetch("http://localhost:8080/admin/list")
        .then(res => res.json())
        .then(data => {
            data.forEach(user => {
                let usersTable = `$(
                        <tr>
                            <td>${user.id}</td>
                            <td>${user.username}</td>
                            <td>${user.lastName}</td>
                            <td>${user.age}</td>   
                            <td>${user.email}</td>
                            <td>${user.shortRole}</td>
                            <td>
                                <button type="button" class="btn btn-sm btn-info"
                                data-bs-toogle="modal"
                                data-bs-target="#editModal"
                                onclick="editModalData(${user.id})">Edit</button>
                            </td>
                            <td>
                                <button type="button" class="btn btn-sm btn-danger" 
                                data-toggle="modal"
                                data-bs-target="#deleteModal"
                                onclick="deleteModalData(${user.id})">Delete</button>
                            </td>
                        </tr>)`;
                table.append(usersTable);
            })
        })
}