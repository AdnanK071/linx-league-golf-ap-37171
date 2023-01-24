import { View, Text, StyleSheet, Image } from "react-native"
import React from "react"
import Row from "../../../Components/Row"
import { colors } from "../../../theme"
import moment from "moment"

export default function RoundCard({ item, containerStyle, index }) {

  const time = moment(item.when).format('DD/MM/YYYY hh:mm a')
  const date = moment(item.when)
  const today = new moment()
  console.log(date > today ? 'big' : 'small',date)
  return (

    date > today ?

      <View style={[styles.container, containerStyle]}>
        <Row>
          <Row style={{ justifyContent: "flex-start" }}>
            <View style={styles.numberContainer}>
              <View
                style={[
                  styles.numberContainer,
                  {
                    backgroundColor: "rgba(192,192,192,1)",
                    height: 22,
                    width: 22
                  }
                ]}
              >
                <Text style={[styles.text, { color: colors.white }]}>
                  {index}
                </Text>
              </View>
            </View>
            <View style={{ marginLeft: 10 }}>
              <Text style={styles.text}>{time || ''}</Text>
              <Text style={[styles.text, { fontWeight: "700", fontSize: 16 }]}>
                {item.course_name}
              </Text>
            </View>
          </Row>
          <View style={{ flexDirection: "row", marginRight: 7 }}>
            {/* {item?.players?.map
          } */}
            <Image
              style={[
                styles.imgStyle,
                { zIndex: 10, position: "absolute", left: -18, bottom: 2 }
              ]}
              resizeMode={"contain"}
              source={require("../../../assets/images/user1.png")}
            />
            <Image
              style={[styles.imgStyle, { zIndex: -10 }]}
              source={require("../../../assets/images/user2.png")}
              resizeMode={"contain"}
            />
          </View>
        </Row>
      </View>
      :
      <></>
  )
}
const styles = StyleSheet.create({
  container: {
    backgroundColor: "#fff",
    padding: 15,
    paddingBottom: 20,
    borderRadius: 25,
    // marginHorizontal:5
    // marginTop: 5
  },
  numberContainer: {
    backgroundColor: "rgba(192,192,192,0.5)",
    height: 32,
    width: 32,
    borderRadius: 15,
    alignItems: "center",
    justifyContent: "center"
  },
  text: {
    fontSize: 14,
    color: colors.text1
  },
  imgStyle: {
    width: 25,
    height: 25,
    borderRadius: 15
  }
})
