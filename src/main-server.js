// @flow

import { ApolloServer } from 'apollo-server-express';

import { Meteor } from 'meteor/meteor';
import { WebApp } from 'meteor/webapp';
import { Accounts } from 'meteor/accounts-base';
import { check } from 'meteor/check';

const defaultGraphQLOptions = {
  // ensure that a context object is defined for the resolvers
  context: {},
  // error formatting
  formatError: e => ({
    message: e.message,
    locations: e.locations,
    path: e.path,
  }),
  // additional debug logging if execution errors occur in dev mode
  debug: Meteor.isDevelopment,
};

export const getUserForContext = async loginToken => {
  // there is a possible current user connected!
  if (loginToken) {
    // throw an error if the token is not a string
    check(loginToken, String);

    // the hashed token is the key to find the possible current user in the db
    const hashedToken = Accounts._hashLoginToken(loginToken);

    // get the possible current user from the database
    // note: no need of a fiber aware findOne + a fiber aware call break tests
    // runned with practicalmeteor:mocha if eslint is enabled
    const currentUser = await Meteor.users.rawCollection().findOne({
      'services.resume.loginTokens.hashedToken': hashedToken,
    });

    // the current user exists
    if (currentUser) {
      // find the right login token corresponding, the current user may have
      // several sessions logged on different browsers / computers
      const tokenInformation = currentUser.services.resume.loginTokens.find(
        tokenInfo => tokenInfo.hashedToken === hashedToken
      );

      // get an exploitable token expiration date
      const expiresAt = Accounts._tokenExpiration(tokenInformation.when);

      // true if the token is expired
      const isExpired = expiresAt < new Date();

      // if the token is still valid, give access to the current user
      // information in the resolvers context
      if (!isExpired) {
        // return a new context object with the current user & her id
        return {
          user: currentUser,
          userId: currentUser._id,
        };
      }
    }
  }

  return {};
};

export const createApolloServer = async (customOptions = {}) => {
  const options = {
    ...defaultGraphQLOptions,
    ...customOptions,
  };

  const apolloServerOptions = {
    ...options,
    context: async ({ req, ...rest }) => {
      let context = {};
      const loginToken = req.headers['meteor-login-token'];
      const userContext = await getUserForContext(loginToken);

      if (typeof options.context === 'function') {
        context = options.context({ req, rest }, userContext);
      } else {
        ({ context } = options);
      }

      return {
        ...context,
        ...userContext,
      };
    },
  };

  const server = new ApolloServer({ ...apolloServerOptions });
  server.applyMiddleware({ app: WebApp.connectHandlers });
};