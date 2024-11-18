showUserInfo();

function showUserInfo() {
    fetch("http://localhost:8080/user/userList")
        .then(res => res.json())
        .then(user => {
            console.log('userSata', JSON.stringify(user))
            $('#headerEmail').append(user.email);
            $('#headerRole').append(user.shortRole);
            let userList = `$(
                <tr>
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td>${user.lastName}</td>
                    <td>${user.age}</td>   
                    <td>${user.email}</td>
                    <td>${user.shortRole}</td>
                </tr>)`;
            $('#userTable').append(userList);
        })
}