module.exports = (sequelize, DataTypes) => {
  const Vote = sequelize.define('Vote', {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true
    },
    link_id: {
      type: DataTypes.INTEGER,
      allowNull: false
    },
    wallet_id: {
      type: DataTypes.STRING(103),
      allowNull: false
    },
    vote_value: {
      type: DataTypes.TINYINT,
      allowNull: false
    },
    vote_date: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    }
  }, {
    tableName: 'table_votes',
    timestamps: false
  });

  return Vote;
};
