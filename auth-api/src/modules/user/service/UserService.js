import UserRepository from "../repository/userRepository.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as httpStatus from "../../../config/constants/httpStatus.js";
import * as secrets from "../../../config/constants/secrets.js";
import UserException from "../exception/UserException.js";

class UserService {

    async findByEmail(req) {
        try {
            const { authUser } = req;
            const { email } = req.params;
            this.validateRequestData(email);
            let user = await UserRepository.findByEmail(email);
            this.validateUserData(user);
            this.validateAuthenticatedUSer(user, authUser);
            return {
                status: httpStatus.SUCCESS,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                }
            };
        } catch (error) {
            return {
                status: error.status ? error.status : httpStatus.BAD_REQUEST,
                message: error.message,
            };
        }

    }

    async getAccessToken(req) {
        try {
            const { email, password } = req.body;
            this.validateEmailAndPassword(email, password);
            let user = await UserRepository.findByEmail(email);
            this.validateUserData(user);
            await this.validatePassword(password, user.password);
            const authUser = { id: user.id, name: user.name, email: user.email };
            const authToken = jwt.sign({ authUser }, secrets.API_SECRET, { expiresIn: "1d" });
            return {
                status: httpStatus.SUCCESS,
                authToken
            };
        } catch (error) {
            return {
                status: error.status ? error.status : httpStatus.BAD_REQUEST,
                message: error.status,
            };
        }

    }

    validateAuthenticatedUSer(user, authUser) {
        if (!authUser || user.id != authUser.id) {
            throw new UserException(httpStatus.FORBIDDEN, 'You cannot see this user data!');
        }
    }

    validateRequestData(email) {
        if (!email) {
            throw new UserException(httpStatus.BAD_REQUEST, 'User email was not informed!');
        }
    }

    validateUserData(user) {
        if (!user) {
            throw new UserException(httpStatus.BAD_REQUEST, 'User was not found!');
        }
    }

    validateEmailAndPassword(email, password) {
        if (!email || !password) {
            throw new UserException(httpStatus.UNAUTHORIZED, 'Email and Password must be informed!');
        }
    }

    async validatePassword(password, hashPassword) {
        if (!await bcrypt.compare(password, hashPassword)) {
            throw new UserException(httpStatus.UNAUTHORIZED, "Wrong password!")
        }
    }

}

export default new UserService();