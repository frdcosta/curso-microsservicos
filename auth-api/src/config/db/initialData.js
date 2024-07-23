import bcrypt from "bcrypt";
import User from "../../modules/user/model/User.js";

export async function createInitialData() {
    try {
        await User.sync({ force: true });

        let password = await bcrypt.hash("123456", 10);

        await User.create({
            name: 'UserTeste',
            email: 'teste@gmail.com',
            password: password,
        });

        await User.create({
            name: 'UserTeste2',
            email: 'teste2@gmail.com',
            password: password,
        });
    } catch (err) {
        console.log(err);
    }
};