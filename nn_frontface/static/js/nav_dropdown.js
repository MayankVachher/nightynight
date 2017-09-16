const button = document.querySelector('#user_nav_dropdown');
const dropdown = document.querySelector('.dropdown');

button.addEventListener('click', () => {
  dropdown.classList.toggle('is-open');
});
